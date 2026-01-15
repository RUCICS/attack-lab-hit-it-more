
problem3:     file format elf64-x86-64


Disassembly of section .init:

0000000000401000 <_init>:
  401000:	f3 0f 1e fa          	endbr64
  401004:	48 83 ec 08          	sub    rsp,0x8
  401008:	48 8b 05 71 24 00 00 	mov    rax,QWORD PTR [rip+0x2471]        # 403480 <__gmon_start__@Base>
  40100f:	48 85 c0             	test   rax,rax
  401012:	74 02                	je     401016 <_init+0x16>
  401014:	ff d0                	call   rax
  401016:	48 83 c4 08          	add    rsp,0x8
  40101a:	c3                   	ret

Disassembly of section .plt:

0000000000401020 <.plt>:
  401020:	ff 35 6a 24 00 00    	push   QWORD PTR [rip+0x246a]        # 403490 <_GLOBAL_OFFSET_TABLE_+0x8>
  401026:	f2 ff 25 6b 24 00 00 	bnd jmp QWORD PTR [rip+0x246b]        # 403498 <_GLOBAL_OFFSET_TABLE_+0x10>
  40102d:	0f 1f 00             	nop    DWORD PTR [rax]
  401030:	f3 0f 1e fa          	endbr64
  401034:	68 00 00 00 00       	push   0x0
  401039:	f2 e9 e1 ff ff ff    	bnd jmp 401020 <_init+0x20>
  40103f:	90                   	nop
  401040:	f3 0f 1e fa          	endbr64
  401044:	68 01 00 00 00       	push   0x1
  401049:	f2 e9 d1 ff ff ff    	bnd jmp 401020 <_init+0x20>
  40104f:	90                   	nop
  401050:	f3 0f 1e fa          	endbr64
  401054:	68 02 00 00 00       	push   0x2
  401059:	f2 e9 c1 ff ff ff    	bnd jmp 401020 <_init+0x20>
  40105f:	90                   	nop
  401060:	f3 0f 1e fa          	endbr64
  401064:	68 03 00 00 00       	push   0x3
  401069:	f2 e9 b1 ff ff ff    	bnd jmp 401020 <_init+0x20>
  40106f:	90                   	nop
  401070:	f3 0f 1e fa          	endbr64
  401074:	68 04 00 00 00       	push   0x4
  401079:	f2 e9 a1 ff ff ff    	bnd jmp 401020 <_init+0x20>
  40107f:	90                   	nop
  401080:	f3 0f 1e fa          	endbr64
  401084:	68 05 00 00 00       	push   0x5
  401089:	f2 e9 91 ff ff ff    	bnd jmp 401020 <_init+0x20>
  40108f:	90                   	nop
  401090:	f3 0f 1e fa          	endbr64
  401094:	68 06 00 00 00       	push   0x6
  401099:	f2 e9 81 ff ff ff    	bnd jmp 401020 <_init+0x20>
  40109f:	90                   	nop
  4010a0:	f3 0f 1e fa          	endbr64
  4010a4:	68 07 00 00 00       	push   0x7
  4010a9:	f2 e9 71 ff ff ff    	bnd jmp 401020 <_init+0x20>
  4010af:	90                   	nop

Disassembly of section .plt.sec:

00000000004010b0 <puts@plt>:
  4010b0:	f3 0f 1e fa          	endbr64
  4010b4:	f2 ff 25 e5 23 00 00 	bnd jmp QWORD PTR [rip+0x23e5]        # 4034a0 <puts@GLIBC_2.2.5>
  4010bb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010c0 <fread@plt>:
  4010c0:	f3 0f 1e fa          	endbr64
  4010c4:	f2 ff 25 dd 23 00 00 	bnd jmp QWORD PTR [rip+0x23dd]        # 4034a8 <fread@GLIBC_2.2.5>
  4010cb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010d0 <fclose@plt>:
  4010d0:	f3 0f 1e fa          	endbr64
  4010d4:	f2 ff 25 d5 23 00 00 	bnd jmp QWORD PTR [rip+0x23d5]        # 4034b0 <fclose@GLIBC_2.2.5>
  4010db:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010e0 <fprintf@plt>:
  4010e0:	f3 0f 1e fa          	endbr64
  4010e4:	f2 ff 25 cd 23 00 00 	bnd jmp QWORD PTR [rip+0x23cd]        # 4034b8 <fprintf@GLIBC_2.2.5>
  4010eb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004010f0 <memcpy@plt>:
  4010f0:	f3 0f 1e fa          	endbr64
  4010f4:	f2 ff 25 c5 23 00 00 	bnd jmp QWORD PTR [rip+0x23c5]        # 4034c0 <memcpy@GLIBC_2.14>
  4010fb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401100 <fopen@plt>:
  401100:	f3 0f 1e fa          	endbr64
  401104:	f2 ff 25 bd 23 00 00 	bnd jmp QWORD PTR [rip+0x23bd]        # 4034c8 <fopen@GLIBC_2.2.5>
  40110b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401110 <perror@plt>:
  401110:	f3 0f 1e fa          	endbr64
  401114:	f2 ff 25 b5 23 00 00 	bnd jmp QWORD PTR [rip+0x23b5]        # 4034d0 <perror@GLIBC_2.2.5>
  40111b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401120 <exit@plt>:
  401120:	f3 0f 1e fa          	endbr64
  401124:	f2 ff 25 ad 23 00 00 	bnd jmp QWORD PTR [rip+0x23ad]        # 4034d8 <exit@GLIBC_2.2.5>
  40112b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .text:

0000000000401130 <_start>:
  401130:	f3 0f 1e fa          	endbr64
  401134:	31 ed                	xor    ebp,ebp
  401136:	49 89 d1             	mov    r9,rdx
  401139:	5e                   	pop    rsi
  40113a:	48 89 e2             	mov    rdx,rsp
  40113d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
  401141:	50                   	push   rax
  401142:	54                   	push   rsp
  401143:	45 31 c0             	xor    r8d,r8d
  401146:	31 c9                	xor    ecx,ecx
  401148:	48 c7 c7 a8 13 40 00 	mov    rdi,0x4013a8
  40114f:	ff 15 23 23 00 00    	call   QWORD PTR [rip+0x2323]        # 403478 <__libc_start_main@GLIBC_2.34>
  401155:	f4                   	hlt
  401156:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  40115d:	00 00 00 

0000000000401160 <_dl_relocate_static_pie>:
  401160:	f3 0f 1e fa          	endbr64
  401164:	c3                   	ret
  401165:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  40116c:	00 00 00 
  40116f:	90                   	nop

0000000000401170 <deregister_tm_clones>:
  401170:	b8 f0 34 40 00       	mov    eax,0x4034f0
  401175:	48 3d f0 34 40 00    	cmp    rax,0x4034f0
  40117b:	74 13                	je     401190 <deregister_tm_clones+0x20>
  40117d:	b8 00 00 00 00       	mov    eax,0x0
  401182:	48 85 c0             	test   rax,rax
  401185:	74 09                	je     401190 <deregister_tm_clones+0x20>
  401187:	bf f0 34 40 00       	mov    edi,0x4034f0
  40118c:	ff e0                	jmp    rax
  40118e:	66 90                	xchg   ax,ax
  401190:	c3                   	ret
  401191:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  401198:	00 00 00 00 
  40119c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

00000000004011a0 <register_tm_clones>:
  4011a0:	be f0 34 40 00       	mov    esi,0x4034f0
  4011a5:	48 81 ee f0 34 40 00 	sub    rsi,0x4034f0
  4011ac:	48 89 f0             	mov    rax,rsi
  4011af:	48 c1 ee 3f          	shr    rsi,0x3f
  4011b3:	48 c1 f8 03          	sar    rax,0x3
  4011b7:	48 01 c6             	add    rsi,rax
  4011ba:	48 d1 fe             	sar    rsi,1
  4011bd:	74 11                	je     4011d0 <register_tm_clones+0x30>
  4011bf:	b8 00 00 00 00       	mov    eax,0x0
  4011c4:	48 85 c0             	test   rax,rax
  4011c7:	74 07                	je     4011d0 <register_tm_clones+0x30>
  4011c9:	bf f0 34 40 00       	mov    edi,0x4034f0
  4011ce:	ff e0                	jmp    rax
  4011d0:	c3                   	ret
  4011d1:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  4011d8:	00 00 00 00 
  4011dc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

00000000004011e0 <__do_global_dtors_aux>:
  4011e0:	f3 0f 1e fa          	endbr64
  4011e4:	80 3d 1d 23 00 00 00 	cmp    BYTE PTR [rip+0x231d],0x0        # 403508 <completed.0>
  4011eb:	75 13                	jne    401200 <__do_global_dtors_aux+0x20>
  4011ed:	55                   	push   rbp
  4011ee:	48 89 e5             	mov    rbp,rsp
  4011f1:	e8 7a ff ff ff       	call   401170 <deregister_tm_clones>
  4011f6:	c6 05 0b 23 00 00 01 	mov    BYTE PTR [rip+0x230b],0x1        # 403508 <completed.0>
  4011fd:	5d                   	pop    rbp
  4011fe:	c3                   	ret
  4011ff:	90                   	nop
  401200:	c3                   	ret
  401201:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  401208:	00 00 00 00 
  40120c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000401210 <frame_dummy>:
  401210:	f3 0f 1e fa          	endbr64
  401214:	eb 8a                	jmp    4011a0 <register_tm_clones>

0000000000401216 <func1>:
  401216:	f3 0f 1e fa          	endbr64
  40121a:	55                   	push   rbp
  40121b:	48 89 e5             	mov    rbp,rsp
  40121e:	48 83 ec 50          	sub    rsp,0x50
  401222:	89 7d bc             	mov    DWORD PTR [rbp-0x44],edi
  401225:	83 7d bc 72          	cmp    DWORD PTR [rbp-0x44],0x72
  401229:	75 57                	jne    401282 <func1+0x6c>
  40122b:	48 b8 59 6f 75 72 20 	movabs rax,0x63756c2072756f59
  401232:	6c 75 63 
  401235:	48 ba 6b 79 20 6e 75 	movabs rdx,0x65626d756e20796b
  40123c:	6d 62 65 
  40123f:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
  401243:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
  401247:	48 b8 72 20 69 73 20 	movabs rax,0x3431312073692072
  40124e:	31 31 34 
  401251:	ba 00 00 00 00       	mov    edx,0x0
  401256:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  40125a:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
  40125e:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
  401265:	00 
  401266:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
  40126d:	00 
  40126e:	66 c7 45 f0 00 00    	mov    WORD PTR [rbp-0x10],0x0
  401274:	48 8d 45 c0          	lea    rax,[rbp-0x40]
  401278:	48 89 c7             	mov    rdi,rax
  40127b:	e8 30 fe ff ff       	call   4010b0 <puts@plt>
  401280:	eb 4e                	jmp    4012d0 <func1+0xba>
  401282:	48 b8 45 72 72 6f 72 	movabs rax,0x6e6120726f727245
  401289:	20 61 6e 
  40128c:	48 ba 73 77 65 72 21 	movabs rdx,0x2172657773
  401293:	00 00 00 
  401296:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
  40129a:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
  40129e:	48 c7 45 d0 00 00 00 	mov    QWORD PTR [rbp-0x30],0x0
  4012a5:	00 
  4012a6:	48 c7 45 d8 00 00 00 	mov    QWORD PTR [rbp-0x28],0x0
  4012ad:	00 
  4012ae:	48 c7 45 e0 00 00 00 	mov    QWORD PTR [rbp-0x20],0x0
  4012b5:	00 
  4012b6:	48 c7 45 e8 00 00 00 	mov    QWORD PTR [rbp-0x18],0x0
  4012bd:	00 
  4012be:	66 c7 45 f0 00 00    	mov    WORD PTR [rbp-0x10],0x0
  4012c4:	48 8d 45 c0          	lea    rax,[rbp-0x40]
  4012c8:	48 89 c7             	mov    rdi,rax
  4012cb:	e8 e0 fd ff ff       	call   4010b0 <puts@plt>
  4012d0:	bf 00 00 00 00       	mov    edi,0x0
  4012d5:	e8 46 fe ff ff       	call   401120 <exit@plt>

00000000004012da <mov_rdi>:
  4012da:	f3 0f 1e fa          	endbr64
  4012de:	55                   	push   rbp
  4012df:	48 89 e5             	mov    rbp,rsp
  4012e2:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
  4012e6:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  4012ea:	48 89 c7             	mov    rdi,rax
  4012ed:	c3                   	ret
  4012ee:	90                   	nop
  4012ef:	5d                   	pop    rbp
  4012f0:	c3                   	ret

00000000004012f1 <mov_rax>:
  4012f1:	f3 0f 1e fa          	endbr64
  4012f5:	55                   	push   rbp
  4012f6:	48 89 e5             	mov    rbp,rsp
  4012f9:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
  4012fd:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  401301:	48 89 c0             	mov    rax,rax
  401304:	c3                   	ret
  401305:	90                   	nop
  401306:	5d                   	pop    rbp
  401307:	c3                   	ret

0000000000401308 <call_rax>:
  401308:	f3 0f 1e fa          	endbr64
  40130c:	55                   	push   rbp
  40130d:	48 89 e5             	mov    rbp,rsp
  401310:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
  401314:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  401318:	ff d0                	call   rax
  40131a:	c3                   	ret
  40131b:	90                   	nop
  40131c:	5d                   	pop    rbp
  40131d:	c3                   	ret

000000000040131e <jmp_x>:
  40131e:	f3 0f 1e fa          	endbr64
  401322:	55                   	push   rbp
  401323:	48 89 e5             	mov    rbp,rsp
  401326:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
  40132a:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  40132e:	ff e0                	jmp    rax
  401330:	c3                   	ret
  401331:	90                   	nop
  401332:	5d                   	pop    rbp
  401333:	c3                   	ret

0000000000401334 <jmp_xs>:
  401334:	f3 0f 1e fa          	endbr64
  401338:	55                   	push   rbp
  401339:	48 89 e5             	mov    rbp,rsp
  40133c:	48 8b 05 cd 21 00 00 	mov    rax,QWORD PTR [rip+0x21cd]        # 403510 <saved_rsp>
  401343:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  401347:	48 83 45 f8 10       	add    QWORD PTR [rbp-0x8],0x10
  40134c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  401350:	ff e0                	jmp    rax
  401352:	90                   	nop
  401353:	5d                   	pop    rbp
  401354:	c3                   	ret

0000000000401355 <func>:
  401355:	f3 0f 1e fa          	endbr64
  401359:	55                   	push   rbp
  40135a:	48 89 e5             	mov    rbp,rsp
  40135d:	48 83 ec 30          	sub    rsp,0x30
  401361:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
  401365:	48 89 e0             	mov    rax,rsp
  401368:	48 89 05 a1 21 00 00 	mov    QWORD PTR [rip+0x21a1],rax        # 403510 <saved_rsp>
  40136f:	48 8b 4d d8          	mov    rcx,QWORD PTR [rbp-0x28]
  401373:	48 8d 45 e0          	lea    rax,[rbp-0x20]
  401377:	ba 40 00 00 00       	mov    edx,0x40
  40137c:	48 89 ce             	mov    rsi,rcx
  40137f:	48 89 c7             	mov    rdi,rax
  401382:	e8 69 fd ff ff       	call   4010f0 <memcpy@plt>
  401387:	48 8d 05 7a 0c 00 00 	lea    rax,[rip+0xc7a]        # 402008 <_IO_stdin_used+0x8>
  40138e:	48 89 c7             	mov    rdi,rax
  401391:	e8 1a fd ff ff       	call   4010b0 <puts@plt>
  401396:	48 8d 05 93 0c 00 00 	lea    rax,[rip+0xc93]        # 402030 <_IO_stdin_used+0x30>
  40139d:	48 89 c7             	mov    rdi,rax
  4013a0:	e8 0b fd ff ff       	call   4010b0 <puts@plt>
  4013a5:	90                   	nop
  4013a6:	c9                   	leave
  4013a7:	c3                   	ret

00000000004013a8 <main>:
  4013a8:	f3 0f 1e fa          	endbr64
  4013ac:	55                   	push   rbp
  4013ad:	48 89 e5             	mov    rbp,rsp
  4013b0:	48 81 ec 20 01 00 00 	sub    rsp,0x120
  4013b7:	89 bd ec fe ff ff    	mov    DWORD PTR [rbp-0x114],edi
  4013bd:	48 89 b5 e0 fe ff ff 	mov    QWORD PTR [rbp-0x120],rsi
  4013c4:	48 8d 05 93 0c 00 00 	lea    rax,[rip+0xc93]        # 40205e <_IO_stdin_used+0x5e>
  4013cb:	48 89 c7             	mov    rdi,rax
  4013ce:	e8 dd fc ff ff       	call   4010b0 <puts@plt>
  4013d3:	83 bd ec fe ff ff 02 	cmp    DWORD PTR [rbp-0x114],0x2
  4013da:	74 32                	je     40140e <main+0x66>
  4013dc:	48 8b 85 e0 fe ff ff 	mov    rax,QWORD PTR [rbp-0x120]
  4013e3:	48 8b 10             	mov    rdx,QWORD PTR [rax]
  4013e6:	48 8b 05 13 21 00 00 	mov    rax,QWORD PTR [rip+0x2113]        # 403500 <stderr@GLIBC_2.2.5>
  4013ed:	48 8d 0d 7b 0c 00 00 	lea    rcx,[rip+0xc7b]        # 40206f <_IO_stdin_used+0x6f>
  4013f4:	48 89 ce             	mov    rsi,rcx
  4013f7:	48 89 c7             	mov    rdi,rax
  4013fa:	b8 00 00 00 00       	mov    eax,0x0
  4013ff:	e8 dc fc ff ff       	call   4010e0 <fprintf@plt>
  401404:	b8 01 00 00 00       	mov    eax,0x1
  401409:	e9 d1 00 00 00       	jmp    4014df <main+0x137>
  40140e:	48 8b 85 e0 fe ff ff 	mov    rax,QWORD PTR [rbp-0x120]
  401415:	48 83 c0 08          	add    rax,0x8
  401419:	48 8b 00             	mov    rax,QWORD PTR [rax]
  40141c:	48 8d 15 5e 0c 00 00 	lea    rdx,[rip+0xc5e]        # 402081 <_IO_stdin_used+0x81>
  401423:	48 89 d6             	mov    rsi,rdx
  401426:	48 89 c7             	mov    rdi,rax
  401429:	e8 d2 fc ff ff       	call   401100 <fopen@plt>
  40142e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  401432:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
  401437:	75 19                	jne    401452 <main+0xaa>
  401439:	48 8d 05 43 0c 00 00 	lea    rax,[rip+0xc43]        # 402083 <_IO_stdin_used+0x83>
  401440:	48 89 c7             	mov    rdi,rax
  401443:	e8 c8 fc ff ff       	call   401110 <perror@plt>
  401448:	b8 01 00 00 00       	mov    eax,0x1
  40144d:	e9 8d 00 00 00       	jmp    4014df <main+0x137>
  401452:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
  401456:	48 8d 85 f0 fe ff ff 	lea    rax,[rbp-0x110]
  40145d:	48 89 d1             	mov    rcx,rdx
  401460:	ba 00 01 00 00       	mov    edx,0x100
  401465:	be 01 00 00 00       	mov    esi,0x1
  40146a:	48 89 c7             	mov    rdi,rax
  40146d:	e8 4e fc ff ff       	call   4010c0 <fread@plt>
  401472:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
  401476:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
  40147b:	75 22                	jne    40149f <main+0xf7>
  40147d:	48 8d 05 05 0c 00 00 	lea    rax,[rip+0xc05]        # 402089 <_IO_stdin_used+0x89>
  401484:	48 89 c7             	mov    rdi,rax
  401487:	e8 84 fc ff ff       	call   401110 <perror@plt>
  40148c:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  401490:	48 89 c7             	mov    rdi,rax
  401493:	e8 38 fc ff ff       	call   4010d0 <fclose@plt>
  401498:	b8 01 00 00 00       	mov    eax,0x1
  40149d:	eb 40                	jmp    4014df <main+0x137>
  40149f:	48 8d 95 f0 fe ff ff 	lea    rdx,[rbp-0x110]
  4014a6:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
  4014aa:	48 01 d0             	add    rax,rdx
  4014ad:	c6 00 00             	mov    BYTE PTR [rax],0x0
  4014b0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  4014b4:	48 89 c7             	mov    rdi,rax
  4014b7:	e8 14 fc ff ff       	call   4010d0 <fclose@plt>
  4014bc:	48 8d 85 f0 fe ff ff 	lea    rax,[rbp-0x110]
  4014c3:	48 89 c7             	mov    rdi,rax
  4014c6:	e8 8a fe ff ff       	call   401355 <func>
  4014cb:	48 8d 05 bd 0b 00 00 	lea    rax,[rip+0xbbd]        # 40208f <_IO_stdin_used+0x8f>
  4014d2:	48 89 c7             	mov    rdi,rax
  4014d5:	e8 d6 fb ff ff       	call   4010b0 <puts@plt>
  4014da:	b8 00 00 00 00       	mov    eax,0x0
  4014df:	c9                   	leave
  4014e0:	c3                   	ret

Disassembly of section .fini:

00000000004014e4 <_fini>:
  4014e4:	f3 0f 1e fa          	endbr64
  4014e8:	48 83 ec 08          	sub    rsp,0x8
  4014ec:	48 83 c4 08          	add    rsp,0x8
  4014f0:	c3                   	ret
