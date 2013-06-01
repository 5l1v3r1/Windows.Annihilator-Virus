Windows Annihilator Virus
=========================

Windows Annigilator v0.1 by Azizjon Mamashoev  {Progress: 100%}

 Viruss:
 
 	- Crypted
 	- Partially mutating
 	- Perprocess Resident
 
 
  Features:
 
	- Plug-ins managmet. Downloads plug-ins from iternet-site
 	- Splacing CreateProcessInternalW for infection
 	- Infection engine dont infecting setup and self-extracting files, cause them verificates CRC
 	- If virus runned with parametr "-infect %file%" it infects this file and quits
 
  Infect Technic:
 
 	- Enlarging last section, infects almost all executable files. Careful treatment with overlay.
 	  Big files are not infects, cause they need big amount of memory and slows down programm.
 
  TODO:
 
 	- Antidebug
 	- SFC Disabling
