# lonelypotato
Modified version C++ version of RottenPotatoNG (/https://github.com/foxglovesec/RottenPotatoNG). Only exe version.
This version includes the API calls to CreateProcesAsUser() and CreateProcessWithTokenW() in order to execute a 
process passed from command line.
Command line args are:
1) Type of API Call (u) = CreateProcesAsUser, (t) = CreateProcessWithTokenW , (*) = both
2) program to execute (typically a reverse shell via bat file)

I also included a Thread impersonating SYSTEM. See MSFRottenpotato.cpp for more details

