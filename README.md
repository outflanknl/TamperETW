# TamperETW, a proof of concept to demonstrate how CLR ETW events can be filtered/tampered.

MDSec's Adam Chester (@_xpn_) recently published a great blog on how RedTeams can hide the execution of .NET assemblies by disabling .NET ETW telemetry.
In his blog he included a proof of concept code which demonstrates how to dismantle ETW telemetry by patching the native EtwEventWrite function.
More technical details can be found within the following blog: https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/

Based on his research i got triggered and wrote a x64 version / proof of concept that uses native system calls to place an inline hook on the EtwEventWrite function. 
By hooking EtwEventWrite and redirect the program flow to our custom MyEtwEventWrite function, we can intercept the function arguments and inspect or change the data (EVENT_DESCRIPTOR and EVENT_DATA_DESCRIPTOR data structures). We then use the native EtwEventWriteFull function to selectively forward .NET ETW events. In this PoC we only block ETW from sending assembly (CLR) loading events (AssemblyDCStart_V1), but with a little bit more research it might be possible to spoof the assembly names before being submitted with EtwEventWriteFull.

## Usage:

```
Download the TamperETW folder and execute the TamperETW executable within the x64/releases folder (or recompile from source).
When the MessageBox pops up, use Process Explorer or Process Hacker to watch the loaded .NET assemblies (ETW telemetry). 
```

## Credits
PoC Author: Cornelis de Plaa (@Cneelis) / Outflank
Based on research from: Adam Chester (@_xpn_) / MDSec
