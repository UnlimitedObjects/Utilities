return function(src, Upvalues) --// See the example below
    local RUpvalues = {}
    src = src:gsub("<<(%w*)>>", function(Local)
        RUpvalues[Local] = Upvalues[Local] or function() return; end

        return Local
    end)

    local f, e = loadstring(src)

    if e then
        return error(e)
    end

    for i, v in next, RUpvalues do
        getfenv(f)[i] = v
    end

    return f
end
