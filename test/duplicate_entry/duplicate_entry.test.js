"use strict";

// Regression test for GHSA-p634-w6r4-rjp2:
// A crafted archive can declare the same entry name more than once. adm-zip
// kept every entry in its entry list but only the last one in its name lookup
// table, so getEntry()/readFile() (table) and getEntries()/extractAllTo() (list)
// could resolve one name to different content: an application validating an
// entry via getEntry() before extracting could approve one file while a
// different one landed on disk. Such archives are now rejected.

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const pth = require("path");
const Zip = require("../../adm-zip");

const DUPLICATE = /Duplicate entry name/;

// Replace every occurrence of `from` with the same-length `to` in a copy of buf.
function renameAll(buf, from, to) {
    const out = Buffer.from(buf);
    const f = Buffer.from(from);
    const t = Buffer.from(to);
    let count = 0;
    let idx = out.indexOf(f);
    while (idx !== -1) {
        t.copy(out, idx);
        count++;
        idx = out.indexOf(f, idx + f.length);
    }
    return { buf: out, count: count };
}

// Archive with two entries both named "a.txt": the first holds FIRST, the
// second (originally "b.txt", renamed in its local and central headers) SECOND.
function craftDuplicateArchive() {
    const zip = new Zip();
    zip.addFile("a.txt", Buffer.from("FIRST"));
    zip.addFile("b.txt", Buffer.from("SECOND"));
    const renamed = renameAll(zip.toBuffer(), "b.txt", "a.txt");
    // one local file header + one central directory header were rewritten
    assert.strictEqual(renamed.count, 2);
    return renamed.buf;
}

describe("ADM-ZIP - duplicate entry names (GHSA-p634-w6r4-rjp2)", () => {
    it("rejects the archive when its entries are listed", () => {
        const zip = new Zip(craftDuplicateArchive());
        assert.throws(() => zip.getEntries(), DUPLICATE);
    });

    it("rejects the archive when an entry is looked up by name", () => {
        assert.throws(() => new Zip(craftDuplicateArchive()).getEntry("a.txt"), DUPLICATE);
        assert.throws(() => new Zip(craftDuplicateArchive()).readFile("a.txt"), DUPLICATE);
        assert.throws(() => new Zip(craftDuplicateArchive()).readAsText("a.txt"), DUPLICATE);
    });

    it("rejects the archive at load time when entries are read eagerly", () => {
        assert.throws(() => new Zip(craftDuplicateArchive(), { readEntries: true }), DUPLICATE);
    });

    it("refuses to extract the archive instead of writing a different entry than getEntry() returns", () => {
        const target = pth.join(os.tmpdir(), "adm-zip-ghsa-p634-" + process.pid + "-" + Date.now());
        const zip = new Zip(craftDuplicateArchive());
        assert.throws(() => zip.extractAllTo(target, true), DUPLICATE);
        assert.strictEqual(fs.existsSync(target), false);
    });

    it("does not flag distinct names that match Object.prototype members", () => {
        const names = ["constructor", "__proto__", "toString", "hasOwnProperty", "valueOf"];
        const zip = new Zip();
        names.forEach((name, i) => zip.addFile(name, Buffer.from("data" + i)));
        const reopened = new Zip(zip.toBuffer());
        assert.deepStrictEqual(
            reopened
                .getEntries()
                .map((e) => e.entryName)
                .sort(),
            names.slice().sort()
        );
        names.forEach((name, i) => assert.strictEqual(reopened.readFile(name).toString(), "data" + i));
    });

    it("does not flag names that differ only by case or by directory", () => {
        const zip = new Zip();
        zip.addFile("A.txt", Buffer.from("upper"));
        zip.addFile("a.txt", Buffer.from("lower"));
        zip.addFile("dir/a.txt", Buffer.from("nested"));
        const reopened = new Zip(zip.toBuffer(), { readEntries: true });
        assert.strictEqual(reopened.readAsText("A.txt"), "upper");
        assert.strictEqual(reopened.readAsText("a.txt"), "lower");
        assert.strictEqual(reopened.readAsText("dir/a.txt"), "nested");
    });
});
