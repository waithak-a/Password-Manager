const { Keychain } = require("./password-manager");

(async () => {
    const kc = await Keychain.init("pw");
    await kc.set("www.google.com", "googlepw");
    await kc.set("www.example.com", "examplepw");
    const [json, hash] = await kc.dump();

    //swap attack, loaded without the trsted hash
    const obj = JSON.parse(json);
    const keys = Object.keys(obj.kvs);
    [obj.kvs[keys[0]], obj.kvs[keys[1]]] = [obj.kvs[keys[1]], obj.kvs[keys[0]]];
    const kc2 = await Keychain.load("pw", JSON.stringify(obj));
    try { await kc2.get("www.example.com"); console.log("FAIL: swap not detected"); }
    catch (e) { console.log("OK: swap detected by AAD"); }

    // Same tampered data, loaded WITH the trusted hash
    try { await Keychain.load("pw", JSON.stringify(obj), hash); console.log("FAIL"); }
    catch (e) { console.log("OK: checksum caught it"); }

})();