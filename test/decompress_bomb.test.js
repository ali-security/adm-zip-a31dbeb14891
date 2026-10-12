"use strict";

const { expect } = require("chai");
const Zip = require("../adm-zip");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of payload. Unless `crc` is given the payload is
// crc-invalid.
function craftBomb(declaredSize, method, content, crc) {
    const name = Buffer.from("a");
    crc = crc || 0; // deliberately wrong by default: alloc used to happen before the crc check
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});

// Regression test for CVE-2026-92000:
// The inflater capped output at the declared uncompressed size only through
// zlib's maxOutputLength, which the streaming API (used by getDataAsync and the
// other *Async readers) ignores, so the async path decompressed without limit.
// A declared size of 0 also disabled the cap altogether, sync and async. The
// bombs below carry a valid crc so the only thing stopping them is the cap.
describe("decompression bomb (async inflate / declared size 0) - CVE-2026-92000", () => {
    const zlib = require("zlib");
    const crc32 = require("../util").crc32;
    const nodeMajor = +process.versions.node.split(".")[0];

    const payload = Buffer.alloc(1024 * 1024, 0x41); // 1 MB of real output
    const deflated = zlib.deflateRawSync(payload); // ~1 KB on the wire
    const payloadCrc = crc32(payload);
    const bomb = (declared) => new Zip(craftBomb(declared, 8 /* DEFLATED */, deflated, payloadCrc));

    // asserts the async read failed on the size cap and returned no data
    const expectCapped = (done) => (data, err) => {
        try {
            expect(err, "async inflate must enforce the declared size").to.be.an("error");
            expect(err.message).to.match(/exceeds the declared uncompressed size/);
            expect(data.length).to.equal(0);
            done();
        } catch (e) {
            done(e);
        }
    };

    it("sanity: the crafted bomb is a valid entry with an honest declared size", (done) => {
        const honest = bomb(payload.length);
        expect(honest.getEntries()[0].getData().equals(payload)).to.equal(true);
        honest.getEntries()[0].getDataAsync((data, err) => {
            try {
                expect(err).to.equal(undefined);
                expect(data.equals(payload)).to.equal(true);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("getDataAsync stops at the declared size instead of inflating without limit", (done) => {
        bomb(10).getEntries()[0].getDataAsync(expectCapped(done));
    });

    it("getDataAsync does not treat a declared size of 0 as unlimited", (done) => {
        bomb(0).getEntries()[0].getDataAsync(expectCapped(done));
    });

    it("readFileAsync reports the size cap error to the caller", (done) => {
        bomb(0).readFileAsync("a", expectCapped(done));
    });

    it("readAsTextAsync reports the size cap error to the caller", (done) => {
        bomb(10).readAsTextAsync("a", expectCapped(done));
    });

    it("extractAllToAsync fails on the size cap instead of writing the inflated bomb", (done) => {
        const pth = require("path");
        const fs = require("fs");
        const rimraf = require("rimraf");
        const target = pth.join(require("os").tmpdir(), "adm-zip-cve-2026-92000-" + process.pid);
        bomb(0).extractAllToAsync(target, true, false, (err) => {
            try {
                expect(err, "extractAllToAsync must enforce the declared size").to.be.an("error");
                expect(err.message).to.match(/exceeds the declared uncompressed size/);
                expect(fs.existsSync(pth.join(target, "a"))).to.equal(false);
                done();
            } catch (e) {
                done(e);
            } finally {
                rimraf.sync(target);
            }
        });
    });

    it("getData stops at the declared size", function () {
        // the sync cap relies on zlib's maxOutputLength (Node >= 15)
        if (nodeMajor < 15) this.skip();
        expect(() => bomb(10).getEntries()[0].getData()).to.throw(RangeError);
    });

    it("getData does not treat a declared size of 0 as unlimited", function () {
        // the sync cap relies on zlib's maxOutputLength (Node >= 15)
        if (nodeMajor < 15) this.skip();
        expect(() => bomb(0).getEntries()[0].getData()).to.throw(RangeError);
    });

    it("getDataAsync reports a malformed deflate stream instead of crashing", (done) => {
        // 0xff starts a final block of the reserved type 3 -> Z_DATA_ERROR
        const zip = new Zip(craftBomb(10, 8 /* DEFLATED */, Buffer.from([0xff, 0xff, 0xff, 0xff])));
        zip.getEntries()[0].getDataAsync((data, err) => {
            try {
                expect(err).to.be.an("error");
                expect(data.length).to.equal(0);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("still reads a genuinely empty DEFLATED entry declaring size 0", (done) => {
        const zip = new Zip(craftBomb(0, 8 /* DEFLATED */, zlib.deflateRawSync(Buffer.alloc(0)), 0));
        expect(zip.getEntries()[0].getData().length).to.equal(0);
        zip.getEntries()[0].getDataAsync((data, err) => {
            try {
                expect(err).to.equal(undefined);
                expect(data.length).to.equal(0);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("still reads a legitimate DEFLATED entry asynchronously", (done) => {
        const zip = new Zip();
        const text = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", text);
        new Zip(zip.toBuffer()).readFileAsync("d.txt", (data, err) => {
            try {
                expect(err).to.equal(undefined);
                expect(data.equals(text)).to.equal(true);
                done();
            } catch (e) {
                done(e);
            }
        });
    });
});
