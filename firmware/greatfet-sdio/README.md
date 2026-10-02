# GreatFET SD/SDIO Host

`sdio.c` and `sdio.h` implement a low-level SD/SDIO host class for the GreatFET
firmware. They let the GreatFET drive a card directly, issue arbitrary SD and
vendor commands, and assert a synchronization trigger on selected packets.

Build them as part of the GreatFET firmware
(https://github.com/greatscottgadgets/greatfet).
