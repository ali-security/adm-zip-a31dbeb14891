"use strict";

// Regression test for CVE-2026-76845:
// sanitize() only proves that an entry's textual path stays under the target
// directory. When a symlink already exists inside the target directory,
// extraction followed it (open()/mkdir() resolve symlinks) and wrote, overwrote
// or created files and folders outside the target. Extraction must now refuse
// any path whose components below the target directory are symlinks.

const { expect } = require("chai");
const fs = require("fs");
const os = require("os");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../../adm-zip");

const isWin = process.platform === "win32";
const IN_THE_WAY = /^ADM-ZIP: There is a file in the way/;
const CANT_CREATE_FOLDER = /^Unable to create folder/;

// Build an archive from [name, content] pairs (content null => directory entry)
// and reload it from its serialized form, the way an attacker's file would be.
function archive(entries) {
    const zip = new Zip();
    for (const [name, content] of entries) {
        zip.addFile(name, content === null ? null : Buffer.from(content));
    }
    return new Zip(zip.toBuffer());
}

// Directory link: junctions on Windows need no privilege and lstat reports them
// as symbolic links, exactly like the reparse points an attacker would plant.
function linkDir(ctx, target, link) {
    try {
        fs.symlinkSync(target, link, isWin ? "junction" : "dir");
    } catch (e) {
        ctx.skip();
    }
}

function linkFile(ctx, target, link) {
    try {
        fs.symlinkSync(target, link, "file");
    } catch (e) {
        ctx.skip();
    }
}

function expectRejected(promise, pattern) {
    return promise.then(
        function () {
            throw new Error("extraction was expected to fail");
        },
        function (err) {
            expect(err).to.be.an("error");
            expect(err.message).to.match(pattern);
        }
    );
}

describe("ADM-ZIP - extraction through pre-existing symlinks (CVE-2026-76845)", function () {
    let base, target, outside;

    beforeEach(function () {
        base = fs.mkdtempSync(pth.join(os.tmpdir(), "adm-zip-symlink-"));
        target = pth.join(base, "target");
        outside = pth.join(base, "outside");
        fs.mkdirSync(target);
        fs.mkdirSync(outside);
    });

    afterEach(function () {
        rimraf.sync(base);
    });

    describe("extractAllTo", function () {
        it("does not write a file through a symlinked directory", function () {
            linkDir(this, outside, pth.join(target, "link"));
            const zip = archive([["link/evil.txt", "pwned"]]);

            expect(() => zip.extractAllTo(target, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.equal(false);
        });

        it("does not overwrite a file through a symlink", function () {
            const secret = pth.join(outside, "secret.txt");
            fs.writeFileSync(secret, "original");
            linkFile(this, secret, pth.join(target, "victim.txt"));
            const zip = archive([["victim.txt", "pwned"]]);

            expect(() => zip.extractAllTo(target, true)).to.throw(IN_THE_WAY);
            expect(fs.readFileSync(secret, "utf8")).to.equal("original");
        });

        it("does not create a file through a dangling symlink", function () {
            const created = pth.join(outside, "created.txt");
            linkFile(this, created, pth.join(target, "victim.txt"));
            const zip = archive([["victim.txt", "pwned"]]);

            expect(() => zip.extractAllTo(target, false)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(created)).to.equal(false);
        });

        it("does not create a directory through a symlinked directory", function () {
            linkDir(this, outside, pth.join(target, "link"));
            const zip = archive([["link/sub/", null]]);

            expect(() => zip.extractAllTo(target, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "sub"))).to.equal(false);
        });
    });

    describe("extractEntryTo", function () {
        it("does not write a file entry through a symlinked directory", function () {
            linkDir(this, outside, pth.join(target, "link"));
            const zip = archive([["link/evil.txt", "pwned"]]);

            expect(() => zip.extractEntryTo("link/evil.txt", target, true, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.equal(false);
        });

        it("does not write to an outFileName that goes through a symlinked directory", function () {
            linkDir(this, outside, pth.join(target, "link"));
            const zip = archive([["a.txt", "pwned"]]);

            expect(() => zip.extractEntryTo("a.txt", target, true, true, false, "link/out.txt")).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "out.txt"))).to.equal(false);
        });

        it("does not write the children of a directory entry through a symlinked directory", function () {
            linkDir(this, outside, pth.join(target, "link"));
            const zip = archive([
                ["link/", null],
                ["link/evil.txt", "pwned"]
            ]);

            expect(() => zip.extractEntryTo("link/", target, true, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.equal(false);
        });

        it("does not overwrite a file through a symlink when the entry path is dropped", function () {
            const secret = pth.join(outside, "secret.txt");
            fs.writeFileSync(secret, "original");
            linkFile(this, secret, pth.join(target, "victim.txt"));
            const zip = archive([["folder/victim.txt", "pwned"]]);

            expect(() => zip.extractEntryTo("folder/victim.txt", target, false, true)).to.throw(IN_THE_WAY);
            expect(fs.readFileSync(secret, "utf8")).to.equal("original");
        });
    });

    describe("extractAllToAsync", function () {
        it("does not write a file through a symlinked directory", function (done) {
            linkDir(this, outside, pth.join(target, "link"));
            const zip = archive([["link/evil.txt", "pwned"]]);

            let called = false;
            zip.extractAllToAsync(target, true, false, function (err) {
                if (called) return;
                called = true;
                try {
                    expect(err).to.be.an("error");
                    expect(err.message).to.match(IN_THE_WAY);
                    expect(fs.existsSync(pth.join(outside, "evil.txt"))).to.equal(false);
                    done();
                } catch (e) {
                    done(e);
                }
            });
        });

        it("does not overwrite a file through a symlink", function () {
            const secret = pth.join(outside, "secret.txt");
            fs.writeFileSync(secret, "original");
            linkFile(this, secret, pth.join(target, "victim.txt"));
            const zip = archive([["victim.txt", "pwned"]]);

            return expectRejected(zip.extractAllToAsync(target, true), IN_THE_WAY).then(function () {
                expect(fs.readFileSync(secret, "utf8")).to.equal("original");
            });
        });

        it("does not create a directory through a symlinked directory", function () {
            linkDir(this, outside, pth.join(target, "link"));
            const zip = archive([["link/sub/", null]]);

            return expectRejected(zip.extractAllToAsync(target, true), CANT_CREATE_FOLDER).then(function () {
                expect(fs.existsSync(pth.join(outside, "sub"))).to.equal(false);
            });
        });
    });

    describe("legitimate extraction", function () {
        it("still extracts into real directories and over real files", function () {
            fs.mkdirSync(pth.join(target, "sub"));
            fs.writeFileSync(pth.join(target, "sub", "existing.txt"), "old");
            const zip = archive([
                ["sub/existing.txt", "new"],
                ["sub/deeper/file.txt", "content"]
            ]);

            zip.extractAllTo(target, true);
            expect(fs.readFileSync(pth.join(target, "sub", "existing.txt"), "utf8")).to.equal("new");
            expect(fs.readFileSync(pth.join(target, "sub", "deeper", "file.txt"), "utf8")).to.equal("content");
        });

        it("still extracts when the target directory itself is reached through a symlink", function () {
            const real = pth.join(base, "real");
            fs.mkdirSync(real);
            const viaLink = pth.join(base, "via-link");
            linkDir(this, real, viaLink);
            const zip = archive([
                ["dir/", null],
                ["dir/a.txt", "a"],
                ["b.txt", "b"]
            ]);

            zip.extractAllTo(viaLink, true);
            expect(fs.readFileSync(pth.join(real, "dir", "a.txt"), "utf8")).to.equal("a");
            expect(fs.readFileSync(pth.join(real, "b.txt"), "utf8")).to.equal("b");

            zip.extractEntryTo("b.txt", viaLink, true, true, false, "c.txt");
            expect(fs.readFileSync(pth.join(real, "c.txt"), "utf8")).to.equal("b");
        });

        it("ignores symlinks that are not on the extracted path", function () {
            linkDir(this, outside, pth.join(target, "link"));
            const zip = archive([["other/file.txt", "content"]]);

            return zip.extractAllToAsync(target, true).then(function () {
                expect(fs.readFileSync(pth.join(target, "other", "file.txt"), "utf8")).to.equal("content");
                expect(fs.readdirSync(outside)).to.deep.equal([]);
            });
        });
    });
});
