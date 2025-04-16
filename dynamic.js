const func = ptr(0x018D5E00)

function memscn(module, pattern) {
    var matches = Memory.scanSync(module.base, module.size, pattern)
    return matches.length > 0 ? matches[0].address : null
}

function ba2arr(ba) {
    var result = []
    var arr = new Uint8Array(ba)
    for (var i = 0; i < arr.length; i++)
        result.push(arr[i])
    return result
}

Interceptor.attach(func, {
    onEnter(args) {
        var tmp = args[0].readByteArray(0x100)
        //console.log(tmp)
        var data = ba2arr(tmp)
        send(JSON.stringify(data))

        const method = args[0].add(6).readCString()
        console.log(method)
        console.log(hexdump(tmp))
    }
})
