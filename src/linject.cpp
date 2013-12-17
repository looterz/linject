
#include "linject.h"

// Bootil Library
using namespace Bootil;

int main( int argc, char* argv[] )
{
        Debug::SuppressPopups( true );

        CommandLine::Set( argc, argv );

        Console::FGColorPush( Console::Green );
        Output::Msg( "Lightweight Injection Tool 1.0\n\n" );
        Console::FGColorPop();

        BString strCommand = String::GetLower( CommandLine::GetArg( 0 ) );

		if (strCommand == "inject")
		{
			BString strProcess = CommandLine::GetSwitch("-process", "");

			if (strProcess == "")
			{
				Output::Msg("Missing -process (the process to inject into)\n");
				exit(1);
			}

			BString strDll = CommandLine::GetSwitch("-dll", "");

			if (strDll == "")
			{
				Output::Msg("Missing -dll (the dll to inject)\n");
				exit(1);
			}

			if (!File::Exists(strDll))
			{
				Output::Warning("Could not locate %s\n", strDll.c_str());
				exit(1);
			}

			return Injector::StartInject(strProcess, strDll);
		}

		if (strCommand == "eject")
		{
			BString strProcess = CommandLine::GetSwitch("-process", "");

			if (strProcess == "")
			{
				Output::Warning("Missing -process (the process to inject into)\n");
				exit(1);
			}

			BString strDll = CommandLine::GetSwitch("-dll", "");

			if (strDll == "")
			{
				Output::Warning("Missing -dll (the dll to inject)\n");
				exit(1);
			}

			if (!File::Exists(strDll))
			{
				Output::Warning("Could not locate %s\n", strDll.c_str());
				exit(1);
			}

			return Injector::StartEject(strProcess, strDll);
		}

		if (strCommand == "dump")
		{
			BString strProcess = CommandLine::GetSwitch("-process", "");

			if (strProcess == "")
			{
				Output::Warning("Missing -process (the process to dump modules from)\n");
				exit(1);
			}

			DWORD PID = Injector::GetProcess(strProcess);

			if (PID == 0)
			{
				Output::Warning("Could not find process %s\n", strProcess.c_str());

				return 0;
			}

			Output::Msg("Dumping modules in use by %s [PID %d]\n", strProcess.c_str(), PID);

			Injector::DumpModules(PID);

			return 0;
		}

        // Help
        Output::Msg( "Usage:\n\n" );

		const BString Help = "Inject DLL Into Process:\n\n"
			"  linject inject -process proc.exe -dll .\\payload.dll\n\n"
			"Eject DLL From Process:\n\n"
			"  linject eject -process proc.exe -dll .\\payload.dll\n\n"
			"Dump Modules in use by Process:\n\n"
			"  linject dump -process proc.exe\n";

		Output::Msg(Help.c_str());

        return 0;
}
