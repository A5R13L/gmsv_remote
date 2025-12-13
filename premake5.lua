PROJECT_GENERATOR_VERSION = 3

local gmcommon = "./garrysmod_common_64"
include(gmcommon)

newoption({
	trigger = "tag_version",
	value = "string",
	description = "The current tag version of the repository"
})

local function PostSetup(bits)
	includedirs("source/thirdparty/base64/include")
	includedirs("source/thirdparty/ixwebsocket/include")
	includedirs("source/thirdparty/nlohmann/include")
	includedirs("source/thirdparty/xor/include")

	filter("system:windows")
		links({"crypt32", "bcrypt", "ws2_32"})

	filter("system:linux")
		if bits == 64 then
			libdirs("source/thirdparty/ixwebsocket/libs/x64")
		else
			libdirs("source/thirdparty/ixwebsocket/libs/x32")
		end

		links{"ixwebsocket", "ssl", "crypto", "z", "pthread"}

	filter {}
		defines{"REMOTE_VERSION=\"" .. (_OPTIONS["tag_version"] or "unknown") .. "\""}
end

CreateWorkspace({name = "remote_64", abi_compatible = false, path = "projects/x64/" .. os.target() .. "/" .. _ACTION})
	CreateProject({serverside = true, source_path = "source", manual_files = false })
		PostSetup(64)
		IncludeHelpersExtended()
		IncludeSDKCommon()
		IncludeSDKTier0()
		IncludeSDKTier1()
		IncludeDetouring()
		IncludeScanning()
		files({"source/**/*.*"})

gmcommon = "./garrysmod_common_32"
include(gmcommon)

CreateWorkspace({name = "remote_32", abi_compatible = false, path = "projects/x32/" .. os.target() .. "/" .. _ACTION})
	CreateProject({serverside = true, source_path = "source", manual_files = false})
		PostSetup(32)
		IncludeHelpersExtended()
		IncludeSDKCommon()
		IncludeSDKTier0()
		IncludeSDKTier1()
		IncludeDetouring()
		IncludeScanning()
		files({"source/**/*.*"})