
problem4:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64
    1004:	48 83 ec 08          	sub    rsp,0x8
    1008:	48 8b 05 d9 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fd9]        # 3fe8 <__gmon_start__@Base>
    100f:	48 85 c0             	test   rax,rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	call   rax
    1016:	48 83 c4 08          	add    rsp,0x8
    101a:	c3                   	ret

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 6a 2f 00 00    	push   QWORD PTR [rip+0x2f6a]        # 3f90 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	ff 25 6c 2f 00 00    	jmp    QWORD PTR [rip+0x2f6c]        # 3f98 <_GLOBAL_OFFSET_TABLE_+0x10>
    102c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
    1030:	f3 0f 1e fa          	endbr64
    1034:	68 00 00 00 00       	push   0x0
    1039:	e9 e2 ff ff ff       	jmp    1020 <_init+0x20>
    103e:	66 90                	xchg   ax,ax
    1040:	f3 0f 1e fa          	endbr64
    1044:	68 01 00 00 00       	push   0x1
    1049:	e9 d2 ff ff ff       	jmp    1020 <_init+0x20>
    104e:	66 90                	xchg   ax,ax
    1050:	f3 0f 1e fa          	endbr64
    1054:	68 02 00 00 00       	push   0x2
    1059:	e9 c2 ff ff ff       	jmp    1020 <_init+0x20>
    105e:	66 90                	xchg   ax,ax
    1060:	f3 0f 1e fa          	endbr64
    1064:	68 03 00 00 00       	push   0x3
    1069:	e9 b2 ff ff ff       	jmp    1020 <_init+0x20>
    106e:	66 90                	xchg   ax,ax
    1070:	f3 0f 1e fa          	endbr64
    1074:	68 04 00 00 00       	push   0x4
    1079:	e9 a2 ff ff ff       	jmp    1020 <_init+0x20>
    107e:	66 90                	xchg   ax,ax
    1080:	f3 0f 1e fa          	endbr64
    1084:	68 05 00 00 00       	push   0x5
    1089:	e9 92 ff ff ff       	jmp    1020 <_init+0x20>
    108e:	66 90                	xchg   ax,ax
    1090:	f3 0f 1e fa          	endbr64
    1094:	68 06 00 00 00       	push   0x6
    1099:	e9 82 ff ff ff       	jmp    1020 <_init+0x20>
    109e:	66 90                	xchg   ax,ax

Disassembly of section .plt.got:

00000000000010a0 <__cxa_finalize@plt>:
    10a0:	f3 0f 1e fa          	endbr64
    10a4:	ff 25 4e 2f 00 00    	jmp    QWORD PTR [rip+0x2f4e]        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    10aa:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

Disassembly of section .plt.sec:

00000000000010b0 <puts@plt>:
    10b0:	f3 0f 1e fa          	endbr64
    10b4:	ff 25 e6 2e 00 00    	jmp    QWORD PTR [rip+0x2ee6]        # 3fa0 <puts@GLIBC_2.2.5>
    10ba:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

00000000000010c0 <strlen@plt>:
    10c0:	f3 0f 1e fa          	endbr64
    10c4:	ff 25 de 2e 00 00    	jmp    QWORD PTR [rip+0x2ede]        # 3fa8 <strlen@GLIBC_2.2.5>
    10ca:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

00000000000010d0 <__stack_chk_fail@plt>:
    10d0:	f3 0f 1e fa          	endbr64
    10d4:	ff 25 d6 2e 00 00    	jmp    QWORD PTR [rip+0x2ed6]        # 3fb0 <__stack_chk_fail@GLIBC_2.4>
    10da:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

00000000000010e0 <printf@plt>:
    10e0:	f3 0f 1e fa          	endbr64
    10e4:	ff 25 ce 2e 00 00    	jmp    QWORD PTR [rip+0x2ece]        # 3fb8 <printf@GLIBC_2.2.5>
    10ea:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

00000000000010f0 <__isoc99_scanf@plt>:
    10f0:	f3 0f 1e fa          	endbr64
    10f4:	ff 25 c6 2e 00 00    	jmp    QWORD PTR [rip+0x2ec6]        # 3fc0 <__isoc99_scanf@GLIBC_2.7>
    10fa:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

0000000000001100 <exit@plt>:
    1100:	f3 0f 1e fa          	endbr64
    1104:	ff 25 be 2e 00 00    	jmp    QWORD PTR [rip+0x2ebe]        # 3fc8 <exit@GLIBC_2.2.5>
    110a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

0000000000001110 <__ctype_b_loc@plt>:
    1110:	f3 0f 1e fa          	endbr64
    1114:	ff 25 b6 2e 00 00    	jmp    QWORD PTR [rip+0x2eb6]        # 3fd0 <__ctype_b_loc@GLIBC_2.3>
    111a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

Disassembly of section .text:

0000000000001120 <_start>:
    1120:	f3 0f 1e fa          	endbr64
    1124:	31 ed                	xor    ebp,ebp
    1126:	49 89 d1             	mov    r9,rdx
    1129:	5e                   	pop    rsi
    112a:	48 89 e2             	mov    rdx,rsp
    112d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
    1131:	50                   	push   rax
    1132:	54                   	push   rsp
    1133:	45 31 c0             	xor    r8d,r8d
    1136:	31 c9                	xor    ecx,ecx
    1138:	48 8d 3d e1 02 00 00 	lea    rdi,[rip+0x2e1]        # 1420 <main>
    113f:	ff 15 93 2e 00 00    	call   QWORD PTR [rip+0x2e93]        # 3fd8 <__libc_start_main@GLIBC_2.34>
    1145:	f4                   	hlt
    1146:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    114d:	00 00 00 

0000000000001150 <deregister_tm_clones>:
    1150:	48 8d 3d b9 2e 00 00 	lea    rdi,[rip+0x2eb9]        # 4010 <__TMC_END__>
    1157:	48 8d 05 b2 2e 00 00 	lea    rax,[rip+0x2eb2]        # 4010 <__TMC_END__>
    115e:	48 39 f8             	cmp    rax,rdi
    1161:	74 15                	je     1178 <deregister_tm_clones+0x28>
    1163:	48 8b 05 76 2e 00 00 	mov    rax,QWORD PTR [rip+0x2e76]        # 3fe0 <_ITM_deregisterTMCloneTable@Base>
    116a:	48 85 c0             	test   rax,rax
    116d:	74 09                	je     1178 <deregister_tm_clones+0x28>
    116f:	ff e0                	jmp    rax
    1171:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    1178:	c3                   	ret
    1179:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

0000000000001180 <register_tm_clones>:
    1180:	48 8d 3d 89 2e 00 00 	lea    rdi,[rip+0x2e89]        # 4010 <__TMC_END__>
    1187:	48 8d 35 82 2e 00 00 	lea    rsi,[rip+0x2e82]        # 4010 <__TMC_END__>
    118e:	48 29 fe             	sub    rsi,rdi
    1191:	48 89 f0             	mov    rax,rsi
    1194:	48 c1 ee 3f          	shr    rsi,0x3f
    1198:	48 c1 f8 03          	sar    rax,0x3
    119c:	48 01 c6             	add    rsi,rax
    119f:	48 d1 fe             	sar    rsi,1
    11a2:	74 14                	je     11b8 <register_tm_clones+0x38>
    11a4:	48 8b 05 45 2e 00 00 	mov    rax,QWORD PTR [rip+0x2e45]        # 3ff0 <_ITM_registerTMCloneTable@Base>
    11ab:	48 85 c0             	test   rax,rax
    11ae:	74 08                	je     11b8 <register_tm_clones+0x38>
    11b0:	ff e0                	jmp    rax
    11b2:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    11b8:	c3                   	ret
    11b9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

00000000000011c0 <__do_global_dtors_aux>:
    11c0:	f3 0f 1e fa          	endbr64
    11c4:	80 3d 45 2e 00 00 00 	cmp    BYTE PTR [rip+0x2e45],0x0        # 4010 <__TMC_END__>
    11cb:	75 2b                	jne    11f8 <__do_global_dtors_aux+0x38>
    11cd:	55                   	push   rbp
    11ce:	48 83 3d 22 2e 00 00 	cmp    QWORD PTR [rip+0x2e22],0x0        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    11d5:	00 
    11d6:	48 89 e5             	mov    rbp,rsp
    11d9:	74 0c                	je     11e7 <__do_global_dtors_aux+0x27>
    11db:	48 8b 3d 26 2e 00 00 	mov    rdi,QWORD PTR [rip+0x2e26]        # 4008 <__dso_handle>
    11e2:	e8 b9 fe ff ff       	call   10a0 <__cxa_finalize@plt>
    11e7:	e8 64 ff ff ff       	call   1150 <deregister_tm_clones>
    11ec:	c6 05 1d 2e 00 00 01 	mov    BYTE PTR [rip+0x2e1d],0x1        # 4010 <__TMC_END__>
    11f3:	5d                   	pop    rbp
    11f4:	c3                   	ret
    11f5:	0f 1f 00             	nop    DWORD PTR [rax]
    11f8:	c3                   	ret
    11f9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

0000000000001200 <frame_dummy>:
    1200:	f3 0f 1e fa          	endbr64
    1204:	e9 77 ff ff ff       	jmp    1180 <register_tm_clones>

0000000000001209 <caesar_decrypt>:
    1209:	f3 0f 1e fa          	endbr64
    120d:	55                   	push   rbp
    120e:	48 89 e5             	mov    rbp,rsp
    1211:	48 83 ec 30          	sub    rsp,0x30
    1215:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
    1219:	89 75 d4             	mov    DWORD PTR [rbp-0x2c],esi
    121c:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    1223:	00 00 
    1225:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    1229:	31 c0                	xor    eax,eax
    122b:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    122f:	48 89 c7             	mov    rdi,rax
    1232:	e8 89 fe ff ff       	call   10c0 <strlen@plt>
    1237:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
    123a:	c7 45 f0 00 00 00 00 	mov    DWORD PTR [rbp-0x10],0x0
    1241:	e9 b3 00 00 00       	jmp    12f9 <caesar_decrypt+0xf0>
    1246:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
    1249:	48 63 d0             	movsxd rdx,eax
    124c:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    1250:	48 01 d0             	add    rax,rdx
    1253:	0f b6 00             	movzx  eax,BYTE PTR [rax]
    1256:	88 45 ee             	mov    BYTE PTR [rbp-0x12],al
    1259:	e8 b2 fe ff ff       	call   1110 <__ctype_b_loc@plt>
    125e:	48 8b 00             	mov    rax,QWORD PTR [rax]
    1261:	48 0f be 55 ee       	movsx  rdx,BYTE PTR [rbp-0x12]
    1266:	48 01 d2             	add    rdx,rdx
    1269:	48 01 d0             	add    rax,rdx
    126c:	0f b7 00             	movzx  eax,WORD PTR [rax]
    126f:	0f b7 c0             	movzx  eax,ax
    1272:	25 00 04 00 00       	and    eax,0x400
    1277:	85 c0                	test   eax,eax
    1279:	74 7a                	je     12f5 <caesar_decrypt+0xec>
    127b:	e8 90 fe ff ff       	call   1110 <__ctype_b_loc@plt>
    1280:	48 8b 00             	mov    rax,QWORD PTR [rax]
    1283:	48 0f be 55 ee       	movsx  rdx,BYTE PTR [rbp-0x12]
    1288:	48 01 d2             	add    rdx,rdx
    128b:	48 01 d0             	add    rax,rdx
    128e:	0f b7 00             	movzx  eax,WORD PTR [rax]
    1291:	0f b7 c0             	movzx  eax,ax
    1294:	25 00 02 00 00       	and    eax,0x200
    1299:	85 c0                	test   eax,eax
    129b:	74 07                	je     12a4 <caesar_decrypt+0x9b>
    129d:	b8 61 00 00 00       	mov    eax,0x61
    12a2:	eb 05                	jmp    12a9 <caesar_decrypt+0xa0>
    12a4:	b8 41 00 00 00       	mov    eax,0x41
    12a9:	88 45 ef             	mov    BYTE PTR [rbp-0x11],al
    12ac:	0f be 55 ee          	movsx  edx,BYTE PTR [rbp-0x12]
    12b0:	0f be 45 ef          	movsx  eax,BYTE PTR [rbp-0x11]
    12b4:	29 c2                	sub    edx,eax
    12b6:	89 d0                	mov    eax,edx
    12b8:	2b 45 d4             	sub    eax,DWORD PTR [rbp-0x2c]
    12bb:	83 c0 1a             	add    eax,0x1a
    12be:	48 63 d0             	movsxd rdx,eax
    12c1:	48 69 d2 4f ec c4 4e 	imul   rdx,rdx,0x4ec4ec4f
    12c8:	48 c1 ea 20          	shr    rdx,0x20
    12cc:	c1 fa 03             	sar    edx,0x3
    12cf:	89 c1                	mov    ecx,eax
    12d1:	c1 f9 1f             	sar    ecx,0x1f
    12d4:	29 ca                	sub    edx,ecx
    12d6:	6b ca 1a             	imul   ecx,edx,0x1a
    12d9:	29 c8                	sub    eax,ecx
    12db:	89 c2                	mov    edx,eax
    12dd:	0f b6 45 ef          	movzx  eax,BYTE PTR [rbp-0x11]
    12e1:	8d 0c 02             	lea    ecx,[rdx+rax*1]
    12e4:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
    12e7:	48 63 d0             	movsxd rdx,eax
    12ea:	48 8b 45 d8          	mov    rax,QWORD PTR [rbp-0x28]
    12ee:	48 01 d0             	add    rax,rdx
    12f1:	89 ca                	mov    edx,ecx
    12f3:	88 10                	mov    BYTE PTR [rax],dl
    12f5:	83 45 f0 01          	add    DWORD PTR [rbp-0x10],0x1
    12f9:	8b 45 f0             	mov    eax,DWORD PTR [rbp-0x10]
    12fc:	3b 45 f4             	cmp    eax,DWORD PTR [rbp-0xc]
    12ff:	0f 8c 41 ff ff ff    	jl     1246 <caesar_decrypt+0x3d>
    1305:	90                   	nop
    1306:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    130a:	64 48 2b 04 25 28 00 	sub    rax,QWORD PTR fs:0x28
    1311:	00 00 
    1313:	74 05                	je     131a <caesar_decrypt+0x111>
    1315:	e8 b6 fd ff ff       	call   10d0 <__stack_chk_fail@plt>
    131a:	c9                   	leave
    131b:	c3                   	ret

000000000000131c <func1>:
    131c:	f3 0f 1e fa          	endbr64
    1320:	55                   	push   rbp
    1321:	48 89 e5             	mov    rbp,rsp
    1324:	48 83 ec 10          	sub    rsp,0x10
    1328:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    132f:	00 00 
    1331:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    1335:	31 c0                	xor    eax,eax
    1337:	48 8d 05 ca 0c 00 00 	lea    rax,[rip+0xcca]        # 2008 <_IO_stdin_used+0x8>
    133e:	48 89 c7             	mov    rdi,rax
    1341:	e8 6a fd ff ff       	call   10b0 <puts@plt>
    1346:	90                   	nop
    1347:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    134b:	64 48 2b 04 25 28 00 	sub    rax,QWORD PTR fs:0x28
    1352:	00 00 
    1354:	74 05                	je     135b <func1+0x3f>
    1356:	e8 75 fd ff ff       	call   10d0 <__stack_chk_fail@plt>
    135b:	c9                   	leave
    135c:	c3                   	ret

000000000000135d <func>:
    135d:	f3 0f 1e fa          	endbr64
    1361:	55                   	push   rbp
    1362:	48 89 e5             	mov    rbp,rsp
    1365:	48 83 ec 30          	sub    rsp,0x30
    1369:	89 7d dc             	mov    DWORD PTR [rbp-0x24],edi
    136c:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    1373:	00 00 
    1375:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    1379:	31 c0                	xor    eax,eax
    137b:	c7 45 f0 fe ff ff ff 	mov    DWORD PTR [rbp-0x10],0xfffffffe
    1382:	8b 45 dc             	mov    eax,DWORD PTR [rbp-0x24]
    1385:	89 45 e8             	mov    DWORD PTR [rbp-0x18],eax
    1388:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
    138b:	89 45 f4             	mov    DWORD PTR [rbp-0xc],eax
    138e:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
    1391:	89 c6                	mov    esi,eax
    1393:	48 8d 05 91 0c 00 00 	lea    rax,[rip+0xc91]        # 202b <_IO_stdin_used+0x2b>
    139a:	48 89 c7             	mov    rdi,rax
    139d:	b8 00 00 00 00       	mov    eax,0x0
    13a2:	e8 39 fd ff ff       	call   10e0 <printf@plt>
    13a7:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
    13aa:	3b 45 f0             	cmp    eax,DWORD PTR [rbp-0x10]
    13ad:	73 11                	jae    13c0 <func+0x63>
    13af:	48 8d 05 87 0c 00 00 	lea    rax,[rip+0xc87]        # 203d <_IO_stdin_used+0x3d>
    13b6:	48 89 c7             	mov    rdi,rax
    13b9:	e8 f2 fc ff ff       	call   10b0 <puts@plt>
    13be:	eb 4a                	jmp    140a <func+0xad>
    13c0:	c7 45 ec 00 00 00 00 	mov    DWORD PTR [rbp-0x14],0x0
    13c7:	eb 08                	jmp    13d1 <func+0x74>
    13c9:	83 6d e8 01          	sub    DWORD PTR [rbp-0x18],0x1
    13cd:	83 45 ec 01          	add    DWORD PTR [rbp-0x14],0x1
    13d1:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
    13d4:	3b 45 f0             	cmp    eax,DWORD PTR [rbp-0x10]
    13d7:	72 f0                	jb     13c9 <func+0x6c>
    13d9:	83 7d e8 01          	cmp    DWORD PTR [rbp-0x18],0x1
    13dd:	75 06                	jne    13e5 <func+0x88>
    13df:	83 7d f4 ff          	cmp    DWORD PTR [rbp-0xc],0xffffffff
    13e3:	74 11                	je     13f6 <func+0x99>
    13e5:	48 8d 05 6b 0c 00 00 	lea    rax,[rip+0xc6b]        # 2057 <_IO_stdin_used+0x57>
    13ec:	48 89 c7             	mov    rdi,rax
    13ef:	e8 bc fc ff ff       	call   10b0 <puts@plt>
    13f4:	eb 14                	jmp    140a <func+0xad>
    13f6:	b8 00 00 00 00       	mov    eax,0x0
    13fb:	e8 1c ff ff ff       	call   131c <func1>
    1400:	bf 00 00 00 00       	mov    edi,0x0
    1405:	e8 f6 fc ff ff       	call   1100 <exit@plt>
    140a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    140e:	64 48 2b 04 25 28 00 	sub    rax,QWORD PTR fs:0x28
    1415:	00 00 
    1417:	74 05                	je     141e <func+0xc1>
    1419:	e8 b2 fc ff ff       	call   10d0 <__stack_chk_fail@plt>
    141e:	c9                   	leave
    141f:	c3                   	ret

0000000000001420 <main>:
    1420:	f3 0f 1e fa          	endbr64
    1424:	55                   	push   rbp
    1425:	48 89 e5             	mov    rbp,rsp
    1428:	48 81 ec a0 00 00 00 	sub    rsp,0xa0
    142f:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
    1436:	00 00 
    1438:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    143c:	31 c0                	xor    eax,eax
    143e:	c7 85 64 ff ff ff ff 	mov    DWORD PTR [rbp-0x9c],0xffffffff
    1445:	ff ff ff 
    1448:	8b 85 64 ff ff ff    	mov    eax,DWORD PTR [rbp-0x9c]
    144e:	89 85 68 ff ff ff    	mov    DWORD PTR [rbp-0x98],eax
    1454:	c7 85 6c ff ff ff a0 	mov    DWORD PTR [rbp-0x94],0xf4143da0
    145b:	3d 14 f4 
    145e:	48 8d 05 0b 0c 00 00 	lea    rax,[rip+0xc0b]        # 2070 <_IO_stdin_used+0x70>
    1465:	48 89 c7             	mov    rdi,rax
    1468:	e8 43 fc ff ff       	call   10b0 <puts@plt>
    146d:	48 8d 45 80          	lea    rax,[rbp-0x80]
    1471:	48 89 c6             	mov    rsi,rax
    1474:	48 8d 05 1a 0c 00 00 	lea    rax,[rip+0xc1a]        # 2095 <_IO_stdin_used+0x95>
    147b:	48 89 c7             	mov    rdi,rax
    147e:	b8 00 00 00 00       	mov    eax,0x0
    1483:	e8 68 fc ff ff       	call   10f0 <__isoc99_scanf@plt>
    1488:	48 b8 70 61 6b 61 67 	movabs rax,0x77757867616b6170
    148f:	78 75 77 
    1492:	48 89 85 73 ff ff ff 	mov    QWORD PTR [rbp-0x8d],rax
    1499:	48 b8 78 75 77 71 75 	movabs rax,0x656f7571777578
    14a0:	6f 65 00 
    14a3:	48 89 85 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rax
    14aa:	48 8d 85 73 ff ff ff 	lea    rax,[rbp-0x8d]
    14b1:	be 0c 00 00 00       	mov    esi,0xc
    14b6:	48 89 c7             	mov    rdi,rax
    14b9:	e8 4b fd ff ff       	call   1209 <caesar_decrypt>
    14be:	48 8d 05 d3 0b 00 00 	lea    rax,[rip+0xbd3]        # 2098 <_IO_stdin_used+0x98>
    14c5:	48 89 c7             	mov    rdi,rax
    14c8:	e8 e3 fb ff ff       	call   10b0 <puts@plt>
    14cd:	48 8d 45 a0          	lea    rax,[rbp-0x60]
    14d1:	48 89 c6             	mov    rsi,rax
    14d4:	48 8d 05 ba 0b 00 00 	lea    rax,[rip+0xbba]        # 2095 <_IO_stdin_used+0x95>
    14db:	48 89 c7             	mov    rdi,rax
    14de:	b8 00 00 00 00       	mov    eax,0x0
    14e3:	e8 08 fc ff ff       	call   10f0 <__isoc99_scanf@plt>
    14e8:	48 b8 75 72 6b 61 67 	movabs rax,0x68757367616b7275
    14ef:	73 75 68 
    14f2:	48 ba 71 79 71 6b 67 	movabs rdx,0x657a6d676b717971
    14f9:	6d 7a 65 
    14fc:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
    1500:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
    1504:	48 b8 74 75 75 69 75 	movabs rax,0x7378787569757574
    150b:	78 78 73 
    150e:	48 ba 75 68 71 6b 61 	movabs rdx,0x617367616b716875
    1515:	67 73 61 
    1518:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
    151c:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
    1520:	48 b8 68 71 6b 61 67 	movabs rax,0x61617367616b7168
    1527:	73 61 61 
    152a:	48 ba 70 65 6f 61 64 	movabs rdx,0x657164616f6570
    1531:	71 65 00 
    1534:	48 89 45 d9          	mov    QWORD PTR [rbp-0x27],rax
    1538:	48 89 55 e1          	mov    QWORD PTR [rbp-0x1f],rdx
    153c:	48 8d 45 c0          	lea    rax,[rbp-0x40]
    1540:	be 0c 00 00 00       	mov    esi,0xc
    1545:	48 89 c7             	mov    rdi,rax
    1548:	e8 bc fc ff ff       	call   1209 <caesar_decrypt>
    154d:	48 8d 05 5c 0b 00 00 	lea    rax,[rip+0xb5c]        # 20b0 <_IO_stdin_used+0xb0>
    1554:	48 89 c7             	mov    rdi,rax
    1557:	e8 54 fb ff ff       	call   10b0 <puts@plt>
    155c:	c7 85 60 ff ff ff 00 	mov    DWORD PTR [rbp-0xa0],0x0
    1563:	00 00 00 
    1566:	48 8d 85 60 ff ff ff 	lea    rax,[rbp-0xa0]
    156d:	48 89 c6             	mov    rsi,rax
    1570:	48 8d 05 6c 0b 00 00 	lea    rax,[rip+0xb6c]        # 20e3 <_IO_stdin_used+0xe3>
    1577:	48 89 c7             	mov    rdi,rax
    157a:	b8 00 00 00 00       	mov    eax,0x0
    157f:	e8 6c fb ff ff       	call   10f0 <__isoc99_scanf@plt>
    1584:	8b 85 60 ff ff ff    	mov    eax,DWORD PTR [rbp-0xa0]
    158a:	89 c7                	mov    edi,eax
    158c:	e8 cc fd ff ff       	call   135d <func>
    1591:	90                   	nop
    1592:	eb d2                	jmp    1566 <main+0x146>

Disassembly of section .fini:

0000000000001594 <_fini>:
    1594:	f3 0f 1e fa          	endbr64
    1598:	48 83 ec 08          	sub    rsp,0x8
    159c:	48 83 c4 08          	add    rsp,0x8
    15a0:	c3                   	ret
