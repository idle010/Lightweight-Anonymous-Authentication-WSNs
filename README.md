##Synopsis

This project contains the implementation details of the proposed scheme in "A Lightweight Anonymous Authentication Protocol with Perfect Forward Secrecy for Wireless Sensor Networks".

##Environmental requirements

Programs can run under Windows, Linux, and Macs. 
Install Proverif 1.96, download Address: http://proverif.inria.fr/
No additional libraries are required. 
ProVerif is a command-line tool which can be executed using the syntax:
           ./proverif [options] hfilenamei

##Code example


C:\Users>E:

E:\>E:\proverif\proverif1.96\proverif.exe E:\proverif\proverif1.96\sensors.pv
File "E:\proverif\proverif1.96\sensors.pv", line 127, character 16 - line 127, character 1
9:
Warning: identifier Kgs rebound
File "E:\proverif\proverif1.96\sensors.pv", line 138, character 16 - line 138, character 1
9:
Warning: identifier PID rebound
File "E:\proverif\proverif1.96\sensors.pv", line 170, character 6 - line 170, character 8:

Warning: identifier Fi rebound
File "E:\proverif\proverif1.96\sensors.pv", line 171, character 6 - line 171, character 7:

Warning: identifier V rebound
Linear part:
Completing equations...
Completed equations:
Convergent part:
XOR(XOR(x_13,y_14),y_14) = x_13
Completing equations...
Completed equations:
XOR(XOR(x_13,y_14),y_14) = x_13
Process:
{1}new ID: bitstring;
{2}new PW: bitstring;
{3}new bi: bitstring;
{4}new Snj: bitstring;
{5}new NC: key;
{6}new Ki: key;
{7}new Fi: bitstring;
{8}new V: bitstring;
{9}insert PsIDKey(PID,ID,Ki,NC);
{10}let Fi_60: bitstring = XOR(Ki,H3(ID,PW,bi)) in
{11}let V_61: bitstring = H1(Mod(Concat(Ki,H3(ID,PW,bi)),CVaule)) in
(
    {12}!
    {13}in(c1, PIDx: bitstring);
    {14}if (PIDx = PID) then
    {33}get PsIDKey(=PID,IDi: bitstring,Kgu: key,NCi: key) in
    {15}event beginGUparam(GWN);
    {16}let xKi: bitstring = XOR(Fi_60,H3(IDi,PW,bi)) in
    {17}if (xKi = Kgu) then
    {18}let V': bitstring = H1(Mod(Concat(xKi,H3(IDi,PW,bi)),CVaule)) in
    {19}if (V' = V_61) then
    {20}let EK: key = H3(IDi,Kgu,NCi) in
    {21}new rA: nonce;
    {22}new T_62: timestamp;
    {23}let vv1: bitstring = H6(IDi,rA,Kgu,PID,NCi,T_62) in
    {24}out(c1, (PID,encrypt((rA,T_62),EK),vv1,isFresh(T_62,true)));
    {25}in(c1, (CT3: bitstring,v4: bitstring));
    {26}let GEK': bitstring = H4(rA,IDi,Kgu,NCi) in
    {27}let (xsk: key,xPID0: bitstring) = decrypt(CT3,GEK') in
    {28}let v'4: bitstring = H4(IDi,xsk,rA,xPID0) in
    {29}if (v'4 = v4) then
    {30}out(c1, H4(Snj,IDi,xPID0,xsk));
    {31}event endUGparam(user);
    {32}out(c1, encrypt(secretA,xsk))
) | (
    {34}!
    {35}in(c1, (xPID: bitstring,CT1: bitstring,v1: bitstring,T': timestamp,checkT: bool));

    {64}get PsIDKey(=xPID,IDi_63: bitstring,Kgu_64: key,NCi_65: key) in
    {36}let EK': key = H3(IDi_63,Kgu_64,NCi_65) in
    {37}let (rAx: nonce,TT: bitstring) = decrypt(CT1,EK') in
    {38}if (checkT = true) then
    {39}event beginUGparam(user);
    {40}let v'1: bitstring = H6(IDi_63,rAx,Kgu_64,PID,NCi_65,TT) in
    {41}if (v'1 = v1) then
    {42}new sk: key;
    {43}event beginSGparam(SN);
    {44}let CT'2: bitstring = XOR(Concat(sk,IDi_63),H3(Kgs,Snj,NSj)) in
    {45}let vv2: bitstring = H5(IDi_63,Snj,sk,Kgs,NSj) in
    {46}out(c2, (CT'2,vv2));
    {47}in(c2, v3: bitstring);
    {48}let v'3: bitstring = H4(Snj,IDi_63,sk,NSj) in
    {49}if (v'3 = v3) then
    {50}event endGSparam(GWN);
    {51}let Kgs_66: key = H1(Kgs) in
    {52}out(c2, encrypt(secretC,sk));
    {53}new PID0: bitstring;
    {54}let GEK: bitstring = H4(rAx,IDi_63,Kgu_64,NCi_65) in
    {55}let vv4: bitstring = H4(IDi_63,sk,rAx,PID0) in
    {56}out(c1, (encrypt((sk,PID0),GEK),vv4));
    {57}in(c1, v5: bitstring);
    {58}let v'5: bitstring = H4(Snj,IDi_63,PID0,sk) in
    {59}if (v'5 = v5) then
    {60}event endGUparam(GWN);
    {61}let PID_67: bitstring = PID0 in
    {62}insert PsIDKey(PID_67,IDi_63,Kgu_64,NCi_65);
    {63}out(c1, encrypt(secretB,sk))
) | (
    {65}!
    {66}in(c2, (CT2: bitstring,v2: bitstring));
    {67}event beginGSparam(GWN);
    {68}let (skx: bitstring,xA2: bitstring) = XOR(CT2,H3(Kgs,Snj,NSj)) in
    {69}let v'2: bitstring = H5(xA2,Snj,skx,Kgs,NSj) in
    {70}if (v'2 = v2) then
    {71}out(c2, H4(Snj,xA2,skx,NSj));
    {72}event endSGparam(SN);
    {73}out(c2, encrypt(secretD,skx))
) | (
    {74}!
    {75}in(c1, (PIDi: bitstring,ID_68: bitstring,shk: key,onek: key));
    {76}if (PIDi <> PID) then
    {77}insert PsIDKey(PIDi,ID_68,shk,onek)
)

-- Query not attacker(secretA[]); not attacker(secretB[]); not attacker(secretC[]); not at
tacker(secretD[])
Completing...
ok, secrecy assumption verified: fact unreachable attacker(Ki[])
ok, secrecy assumption verified: fact unreachable attacker(NC[])
Starting query not attacker(secretA[])
RESULT not attacker(secretA[]) is true.
Starting query not attacker(secretB[])
RESULT not attacker(secretB[]) is true.
Starting query not attacker(secretC[])
RESULT not attacker(secretC[]) is true.
Starting query not attacker(secretD[])
RESULT not attacker(secretD[]) is true.
-- Query inj-event(endSGparam(x_1977)) ==> inj-event(beginSGparam(x_1977))
Completing...
ok, secrecy assumption verified: fact unreachable attacker(Ki[])
ok, secrecy assumption verified: fact unreachable attacker(NC[])
Starting query inj-event(endSGparam(x_1977)) ==> inj-event(beginSGparam(x_1977))
RESULT inj-event(endSGparam(x_1977)) ==> inj-event(beginSGparam(x_1977)) is true.
-- Query inj-event(endGSparam(x_4049)) ==> inj-event(beginGSparam(x_4049))
Completing...
ok, secrecy assumption verified: fact unreachable attacker(Ki[])
ok, secrecy assumption verified: fact unreachable attacker(NC[])
Starting query inj-event(endGSparam(x_4049)) ==> inj-event(beginGSparam(x_4049))
RESULT inj-event(endGSparam(x_4049)) ==> inj-event(beginGSparam(x_4049)) is true.
-- Query inj-event(endGUparam(x_5918)) ==> inj-event(beginGUparam(x_5918))
Completing...
ok, secrecy assumption verified: fact unreachable attacker(Ki[])
ok, secrecy assumption verified: fact unreachable attacker(NC[])
Starting query inj-event(endGUparam(x_5918)) ==> inj-event(beginGUparam(x_5918))
RESULT inj-event(endGUparam(x_5918)) ==> inj-event(beginGUparam(x_5918)) is true.
-- Query inj-event(endUGparam(x_7830)) ==> inj-event(beginUGparam(x_7830))
Completing...
ok, secrecy assumption verified: fact unreachable attacker(Ki[])
ok, secrecy assumption verified: fact unreachable attacker(NC[])
Starting query inj-event(endUGparam(x_7830)) ==> inj-event(beginUGparam(x_7830))
RESULT inj-event(endUGparam(x_7830)) ==> inj-event(beginUGparam(x_7830)) is true.

