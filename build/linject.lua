
project "linject"

	configurations
	{ 
		"Release"
	}

	uuid ( "637965CD-3B86-4CFD-B502-CB9D6F5B7D65" )
	files { "../src/**.*", "../include/**.*" }
	kind "ConsoleApp"
	targetname( "linject" )
	flags { "Symbols", "NoEditAndContinue", "NoPCH", "StaticRuntime", "EnableSSE" }
	targetdir ( "../bin/" .. os.get() .. "/" .. _ACTION )
	includedirs { "../include/" }
	libdirs { "../lib/" }
	
	if os.is( "linux" ) then
		targetname( "linject_linux" )
		links { "pthread" }
		buildoptions { "-fPIC" }
		linkoptions  { "-fPIC" }
	end
	
	if os.is( "macosx" ) then
		targetname( "linject_osx" )
		buildoptions { "-fPIC" }
		linkoptions  { "-fPIC" }
	end

	configuration "Release"
		defines { "NDEBUG" }
		flags{ "OptimizeSpeed", "FloatFast" }
		links( { "bootil_static" } )
