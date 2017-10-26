<p>## Synopsis</p>

<p>This project contains the implementation details of the proposed scheme in &quot;A Lightweight Anonymous Authentication Protocol with Perfect Forward Secrecy for Wireless Sensor Networks&quot;.</p>

<p>## Environmental requirements</p>

<p>Programs can run under Windows, Linux, and Macs.&nbsp;<br />
Install Proverif 1.96, download Address: http://proverif.inria.fr/<br />
No additional libraries are required.&nbsp;<br />
ProVerif is a command-line tool which can be executed using the syntax:<br />
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;./proverif [options] hfilenamei</p>

<p>## Code example</p>

<p><br />
C:\Users&gt;E:</p>

<p>E:\&gt;E:\proverif\proverif1.96\proverif.exe E:\proverif\proverif1.96\sensors.pv<br />
File &quot;E:\proverif\proverif1.96\sensors.pv&quot;, line 127, character 16 - line 127, character 1<br />
9:<br />
Warning: identifier Kgs rebound<br />
File &quot;E:\proverif\proverif1.96\sensors.pv&quot;, line 138, character 16 - line 138, character 1<br />
9:<br />
Warning: identifier PID rebound<br />
File &quot;E:\proverif\proverif1.96\sensors.pv&quot;, line 170, character 6 - line 170, character 8:</p>

<p>Warning: identifier Fi rebound<br />
File &quot;E:\proverif\proverif1.96\sensors.pv&quot;, line 171, character 6 - line 171, character 7:</p>

<p>Warning: identifier V rebound<br />
Linear part:<br />
Completing equations...<br />
Completed equations:<br />
Convergent part:<br />
XOR(XOR(x_13,y_14),y_14) = x_13<br />
Completing equations...<br />
Completed equations:<br />
XOR(XOR(x_13,y_14),y_14) = x_13<br />
Process:<br />
{1}new ID: bitstring;<br />
{2}new PW: bitstring;<br />
{3}new bi: bitstring;<br />
{4}new Snj: bitstring;<br />
{5}new NC: key;<br />
{6}new Ki: key;<br />
{7}new Fi: bitstring;<br />
{8}new V: bitstring;<br />
{9}insert PsIDKey(PID,ID,Ki,NC);<br />
{10}let Fi_60: bitstring = XOR(Ki,H3(ID,PW,bi)) in<br />
{11}let V_61: bitstring = H1(Mod(Concat(Ki,H3(ID,PW,bi)),CVaule)) in<br />
(<br />
&nbsp; &nbsp; {12}!<br />
&nbsp; &nbsp; {13}in(c1, PIDx: bitstring);<br />
&nbsp; &nbsp; {14}if (PIDx = PID) then<br />
&nbsp; &nbsp; {33}get PsIDKey(=PID,IDi: bitstring,Kgu: key,NCi: key) in<br />
&nbsp; &nbsp; {15}event beginGUparam(GWN);<br />
&nbsp; &nbsp; {16}let xKi: bitstring = XOR(Fi_60,H3(IDi,PW,bi)) in<br />
&nbsp; &nbsp; {17}if (xKi = Kgu) then<br />
&nbsp; &nbsp; {18}let V&#39;: bitstring = H1(Mod(Concat(xKi,H3(IDi,PW,bi)),CVaule)) in<br />
&nbsp; &nbsp; {19}if (V&#39; = V_61) then<br />
&nbsp; &nbsp; {20}let EK: key = H3(IDi,Kgu,NCi) in<br />
&nbsp; &nbsp; {21}new rA: nonce;<br />
&nbsp; &nbsp; {22}new T_62: timestamp;<br />
&nbsp; &nbsp; {23}let vv1: bitstring = H6(IDi,rA,Kgu,PID,NCi,T_62) in<br />
&nbsp; &nbsp; {24}out(c1, (PID,encrypt((rA,T_62),EK),vv1,isFresh(T_62,true)));<br />
&nbsp; &nbsp; {25}in(c1, (CT3: bitstring,v4: bitstring));<br />
&nbsp; &nbsp; {26}let GEK&#39;: bitstring = H4(rA,IDi,Kgu,NCi) in<br />
&nbsp; &nbsp; {27}let (xsk: key,xPID0: bitstring) = decrypt(CT3,GEK&#39;) in<br />
&nbsp; &nbsp; {28}let v&#39;4: bitstring = H4(IDi,xsk,rA,xPID0) in<br />
&nbsp; &nbsp; {29}if (v&#39;4 = v4) then<br />
&nbsp; &nbsp; {30}out(c1, H4(Snj,IDi,xPID0,xsk));<br />
&nbsp; &nbsp; {31}event endUGparam(user);<br />
&nbsp; &nbsp; {32}out(c1, encrypt(secretA,xsk))<br />
) | (<br />
&nbsp; &nbsp; {34}!<br />
&nbsp; &nbsp; {35}in(c1, (xPID: bitstring,CT1: bitstring,v1: bitstring,T&#39;: timestamp,checkT: bool));</p>

<p>&nbsp; &nbsp; {64}get PsIDKey(=xPID,IDi_63: bitstring,Kgu_64: key,NCi_65: key) in<br />
&nbsp; &nbsp; {36}let EK&#39;: key = H3(IDi_63,Kgu_64,NCi_65) in<br />
&nbsp; &nbsp; {37}let (rAx: nonce,TT: bitstring) = decrypt(CT1,EK&#39;) in<br />
&nbsp; &nbsp; {38}if (checkT = true) then<br />
&nbsp; &nbsp; {39}event beginUGparam(user);<br />
&nbsp; &nbsp; {40}let v&#39;1: bitstring = H6(IDi_63,rAx,Kgu_64,PID,NCi_65,TT) in<br />
&nbsp; &nbsp; {41}if (v&#39;1 = v1) then<br />
&nbsp; &nbsp; {42}new sk: key;<br />
&nbsp; &nbsp; {43}event beginSGparam(SN);<br />
&nbsp; &nbsp; {44}let CT&#39;2: bitstring = XOR(Concat(sk,IDi_63),H3(Kgs,Snj,NSj)) in<br />
&nbsp; &nbsp; {45}let vv2: bitstring = H5(IDi_63,Snj,sk,Kgs,NSj) in<br />
&nbsp; &nbsp; {46}out(c2, (CT&#39;2,vv2));<br />
&nbsp; &nbsp; {47}in(c2, v3: bitstring);<br />
&nbsp; &nbsp; {48}let v&#39;3: bitstring = H4(Snj,IDi_63,sk,NSj) in<br />
&nbsp; &nbsp; {49}if (v&#39;3 = v3) then<br />
&nbsp; &nbsp; {50}event endGSparam(GWN);<br />
&nbsp; &nbsp; {51}let Kgs_66: key = H1(Kgs) in<br />
&nbsp; &nbsp; {52}out(c2, encrypt(secretC,sk));<br />
&nbsp; &nbsp; {53}new PID0: bitstring;<br />
&nbsp; &nbsp; {54}let GEK: bitstring = H4(rAx,IDi_63,Kgu_64,NCi_65) in<br />
&nbsp; &nbsp; {55}let vv4: bitstring = H4(IDi_63,sk,rAx,PID0) in<br />
&nbsp; &nbsp; {56}out(c1, (encrypt((sk,PID0),GEK),vv4));<br />
&nbsp; &nbsp; {57}in(c1, v5: bitstring);<br />
&nbsp; &nbsp; {58}let v&#39;5: bitstring = H4(Snj,IDi_63,PID0,sk) in<br />
&nbsp; &nbsp; {59}if (v&#39;5 = v5) then<br />
&nbsp; &nbsp; {60}event endGUparam(GWN);<br />
&nbsp; &nbsp; {61}let PID_67: bitstring = PID0 in<br />
&nbsp; &nbsp; {62}insert PsIDKey(PID_67,IDi_63,Kgu_64,NCi_65);<br />
&nbsp; &nbsp; {63}out(c1, encrypt(secretB,sk))<br />
) | (<br />
&nbsp; &nbsp; {65}!<br />
&nbsp; &nbsp; {66}in(c2, (CT2: bitstring,v2: bitstring));<br />
&nbsp; &nbsp; {67}event beginGSparam(GWN);<br />
&nbsp; &nbsp; {68}let (skx: bitstring,xA2: bitstring) = XOR(CT2,H3(Kgs,Snj,NSj)) in<br />
&nbsp; &nbsp; {69}let v&#39;2: bitstring = H5(xA2,Snj,skx,Kgs,NSj) in<br />
&nbsp; &nbsp; {70}if (v&#39;2 = v2) then<br />
&nbsp; &nbsp; {71}out(c2, H4(Snj,xA2,skx,NSj));<br />
&nbsp; &nbsp; {72}event endSGparam(SN);<br />
&nbsp; &nbsp; {73}out(c2, encrypt(secretD,skx))<br />
) | (<br />
&nbsp; &nbsp; {74}!<br />
&nbsp; &nbsp; {75}in(c1, (PIDi: bitstring,ID_68: bitstring,shk: key,onek: key));<br />
&nbsp; &nbsp; {76}if (PIDi &lt;&gt; PID) then<br />
&nbsp; &nbsp; {77}insert PsIDKey(PIDi,ID_68,shk,onek)<br />
)</p>

<p>-- Query not attacker(secretA[]); not attacker(secretB[]); not attacker(secretC[]); not at<br />
tacker(secretD[])<br />
Completing...<br />
ok, secrecy assumption verified: fact unreachable attacker(Ki[])<br />
ok, secrecy assumption verified: fact unreachable attacker(NC[])<br />
Starting query not attacker(secretA[])<br />
RESULT not attacker(secretA[]) is true.<br />
Starting query not attacker(secretB[])<br />
RESULT not attacker(secretB[]) is true.<br />
Starting query not attacker(secretC[])<br />
RESULT not attacker(secretC[]) is true.<br />
Starting query not attacker(secretD[])<br />
RESULT not attacker(secretD[]) is true.<br />
-- Query inj-event(endSGparam(x_1977)) ==&gt; inj-event(beginSGparam(x_1977))<br />
Completing...<br />
ok, secrecy assumption verified: fact unreachable attacker(Ki[])<br />
ok, secrecy assumption verified: fact unreachable attacker(NC[])<br />
Starting query inj-event(endSGparam(x_1977)) ==&gt; inj-event(beginSGparam(x_1977))<br />
RESULT inj-event(endSGparam(x_1977)) ==&gt; inj-event(beginSGparam(x_1977)) is true.<br />
-- Query inj-event(endGSparam(x_4049)) ==&gt; inj-event(beginGSparam(x_4049))<br />
Completing...<br />
ok, secrecy assumption verified: fact unreachable attacker(Ki[])<br />
ok, secrecy assumption verified: fact unreachable attacker(NC[])<br />
Starting query inj-event(endGSparam(x_4049)) ==&gt; inj-event(beginGSparam(x_4049))<br />
RESULT inj-event(endGSparam(x_4049)) ==&gt; inj-event(beginGSparam(x_4049)) is true.<br />
-- Query inj-event(endGUparam(x_5918)) ==&gt; inj-event(beginGUparam(x_5918))<br />
Completing...<br />
ok, secrecy assumption verified: fact unreachable attacker(Ki[])<br />
ok, secrecy assumption verified: fact unreachable attacker(NC[])<br />
Starting query inj-event(endGUparam(x_5918)) ==&gt; inj-event(beginGUparam(x_5918))<br />
RESULT inj-event(endGUparam(x_5918)) ==&gt; inj-event(beginGUparam(x_5918)) is true.<br />
-- Query inj-event(endUGparam(x_7830)) ==&gt; inj-event(beginUGparam(x_7830))<br />
Completing...<br />
ok, secrecy assumption verified: fact unreachable attacker(Ki[])<br />
ok, secrecy assumption verified: fact unreachable attacker(NC[])<br />
Starting query inj-event(endUGparam(x_7830)) ==&gt; inj-event(beginUGparam(x_7830))<br />
RESULT inj-event(endUGparam(x_7830)) ==&gt; inj-event(beginUGparam(x_7830)) is true.</p>
