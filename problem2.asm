
problem2:     file format elf64-x86-64


Disassembly of section .init:

0000000000401000 <_init>:
  401000:	f3 0f 1e fa          	endbr64
  401004:	48 83 ec 08          	sub    rsp,0x8
  401008:	48 8b 05 d1 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fd1]        # 403fe0 <__gmon_start__@Base>
  40100f:	48 85 c0             	test   rax,rax
  401012:	74 02                	je     401016 <_init+0x16>
  401014:	ff d0                	call   rax
  401016:	48 83 c4 08          	add    rsp,0x8
  40101a:	c3                   	ret

Disassembly of section .plt:

0000000000401020 <.plt>:
  401020:	ff 35 ca 2f 00 00    	push   QWORD PTR [rip+0x2fca]        # 403ff0 <_GLOBAL_OFFSET_TABLE_+0x8>
  401026:	ff 25 cc 2f 00 00    	jmp    QWORD PTR [rip+0x2fcc]        # 403ff8 <_GLOBAL_OFFSET_TABLE_+0x10>
  40102c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  401030:	f3 0f 1e fa          	endbr64
  401034:	68 00 00 00 00       	push   0x0
  401039:	e9 e2 ff ff ff       	jmp    401020 <_init+0x20>
  40103e:	66 90                	xchg   ax,ax
  401040:	f3 0f 1e fa          	endbr64
  401044:	68 01 00 00 00       	push   0x1
  401049:	e9 d2 ff ff ff       	jmp    401020 <_init+0x20>
  40104e:	66 90                	xchg   ax,ax
  401050:	f3 0f 1e fa          	endbr64
  401054:	68 02 00 00 00       	push   0x2
  401059:	e9 c2 ff ff ff       	jmp    401020 <_init+0x20>
  40105e:	66 90                	xchg   ax,ax
  401060:	f3 0f 1e fa          	endbr64
  401064:	68 03 00 00 00       	push   0x3
  401069:	e9 b2 ff ff ff       	jmp    401020 <_init+0x20>
  40106e:	66 90                	xchg   ax,ax
  401070:	f3 0f 1e fa          	endbr64
  401074:	68 04 00 00 00       	push   0x4
  401079:	e9 a2 ff ff ff       	jmp    401020 <_init+0x20>
  40107e:	66 90                	xchg   ax,ax
  401080:	f3 0f 1e fa          	endbr64
  401084:	68 05 00 00 00       	push   0x5
  401089:	e9 92 ff ff ff       	jmp    401020 <_init+0x20>
  40108e:	66 90                	xchg   ax,ax
  401090:	f3 0f 1e fa          	endbr64
  401094:	68 06 00 00 00       	push   0x6
  401099:	e9 82 ff ff ff       	jmp    401020 <_init+0x20>
  40109e:	66 90                	xchg   ax,ax
  4010a0:	f3 0f 1e fa          	endbr64
  4010a4:	68 07 00 00 00       	push   0x7
  4010a9:	e9 72 ff ff ff       	jmp    401020 <_init+0x20>
  4010ae:	66 90                	xchg   ax,ax

Disassembly of section .plt.sec:

00000000004010b0 <fread@plt>:
  4010b0:	f3 0f 1e fa          	endbr64
  4010b4:	ff 25 46 2f 00 00    	jmp    QWORD PTR [rip+0x2f46]        # 404000 <fread@GLIBC_2.2.5>
  4010ba:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

00000000004010c0 <fclose@plt>:
  4010c0:	f3 0f 1e fa          	endbr64
  4010c4:	ff 25 3e 2f 00 00    	jmp    QWORD PTR [rip+0x2f3e]        # 404008 <fclose@GLIBC_2.2.5>
  4010ca:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

00000000004010d0 <printf@plt>:
  4010d0:	f3 0f 1e fa          	endbr64
  4010d4:	ff 25 36 2f 00 00    	jmp    QWORD PTR [rip+0x2f36]        # 404010 <printf@GLIBC_2.2.5>
  4010da:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

00000000004010e0 <fprintf@plt>:
  4010e0:	f3 0f 1e fa          	endbr64
  4010e4:	ff 25 2e 2f 00 00    	jmp    QWORD PTR [rip+0x2f2e]        # 404018 <fprintf@GLIBC_2.2.5>
  4010ea:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

00000000004010f0 <memcpy@plt>:
  4010f0:	f3 0f 1e fa          	endbr64
  4010f4:	ff 25 26 2f 00 00    	jmp    QWORD PTR [rip+0x2f26]        # 404020 <memcpy@GLIBC_2.14>
  4010fa:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

0000000000401100 <fopen@plt>:
  401100:	f3 0f 1e fa          	endbr64
  401104:	ff 25 1e 2f 00 00    	jmp    QWORD PTR [rip+0x2f1e]        # 404028 <fopen@GLIBC_2.2.5>
  40110a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

0000000000401110 <perror@plt>:
  401110:	f3 0f 1e fa          	endbr64
  401114:	ff 25 16 2f 00 00    	jmp    QWORD PTR [rip+0x2f16]        # 404030 <perror@GLIBC_2.2.5>
  40111a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

0000000000401120 <exit@plt>:
  401120:	f3 0f 1e fa          	endbr64
  401124:	ff 25 0e 2f 00 00    	jmp    QWORD PTR [rip+0x2f0e]        # 404038 <exit@GLIBC_2.2.5>
  40112a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

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
  401148:	48 c7 c7 cc 12 40 00 	mov    rdi,0x4012cc
  40114f:	ff 15 83 2e 00 00    	call   QWORD PTR [rip+0x2e83]        # 403fd8 <__libc_start_main@GLIBC_2.34>
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
  401170:	b8 50 40 40 00       	mov    eax,0x404050
  401175:	48 3d 50 40 40 00    	cmp    rax,0x404050
  40117b:	74 13                	je     401190 <deregister_tm_clones+0x20>
  40117d:	b8 00 00 00 00       	mov    eax,0x0
  401182:	48 85 c0             	test   rax,rax
  401185:	74 09                	je     401190 <deregister_tm_clones+0x20>
  401187:	bf 50 40 40 00       	mov    edi,0x404050
  40118c:	ff e0                	jmp    rax
  40118e:	66 90                	xchg   ax,ax
  401190:	c3                   	ret
  401191:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  401198:	00 00 00 00 
  40119c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

00000000004011a0 <register_tm_clones>:
  4011a0:	be 50 40 40 00       	mov    esi,0x404050
  4011a5:	48 81 ee 50 40 40 00 	sub    rsi,0x404050
  4011ac:	48 89 f0             	mov    rax,rsi
  4011af:	48 c1 ee 3f          	shr    rsi,0x3f
  4011b3:	48 c1 f8 03          	sar    rax,0x3
  4011b7:	48 01 c6             	add    rsi,rax
  4011ba:	48 d1 fe             	sar    rsi,1
  4011bd:	74 11                	je     4011d0 <register_tm_clones+0x30>
  4011bf:	b8 00 00 00 00       	mov    eax,0x0
  4011c4:	48 85 c0             	test   rax,rax
  4011c7:	74 07                	je     4011d0 <register_tm_clones+0x30>
  4011c9:	bf 50 40 40 00       	mov    edi,0x404050
  4011ce:	ff e0                	jmp    rax
  4011d0:	c3                   	ret
  4011d1:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  4011d8:	00 00 00 00 
  4011dc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

00000000004011e0 <__do_global_dtors_aux>:
  4011e0:	f3 0f 1e fa          	endbr64
  4011e4:	80 3d 7d 2e 00 00 00 	cmp    BYTE PTR [rip+0x2e7d],0x0        # 404068 <completed.0>
  4011eb:	75 13                	jne    401200 <__do_global_dtors_aux+0x20>
  4011ed:	55                   	push   rbp
  4011ee:	48 89 e5             	mov    rbp,rsp
  4011f1:	e8 7a ff ff ff       	call   401170 <deregister_tm_clones>
  4011f6:	c6 05 6b 2e 00 00 01 	mov    BYTE PTR [rip+0x2e6b],0x1        # 404068 <completed.0>
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

0000000000401216 <func2>:
  401216:	f3 0f 1e fa          	endbr64
  40121a:	55                   	push   rbp
  40121b:	48 89 e5             	mov    rbp,rsp
  40121e:	48 83 ec 10          	sub    rsp,0x10
  401222:	89 7d fc             	mov    DWORD PTR [rbp-0x4],edi
  401225:	81 7d fc f8 03 00 00 	cmp    DWORD PTR [rbp-0x4],0x3f8
  40122c:	74 1e                	je     40124c <func2+0x36>
  40122e:	48 8d 05 d3 0d 00 00 	lea    rax,[rip+0xdd3]        # 402008 <_IO_stdin_used+0x8>
  401235:	48 89 c7             	mov    rdi,rax
  401238:	b8 00 00 00 00       	mov    eax,0x0
  40123d:	e8 8e fe ff ff       	call   4010d0 <printf@plt>
  401242:	bf 00 00 00 00       	mov    edi,0x0
  401247:	e8 d4 fe ff ff       	call   401120 <exit@plt>
  40124c:	48 8d 05 e8 0d 00 00 	lea    rax,[rip+0xde8]        # 40203b <_IO_stdin_used+0x3b>
  401253:	48 89 c7             	mov    rdi,rax
  401256:	b8 00 00 00 00       	mov    eax,0x0
  40125b:	e8 70 fe ff ff       	call   4010d0 <printf@plt>
  401260:	bf 00 00 00 00       	mov    edi,0x0
  401265:	e8 b6 fe ff ff       	call   401120 <exit@plt>

000000000040126a <fucc>:
  40126a:	f3 0f 1e fa          	endbr64
  40126e:	55                   	push   rbp
  40126f:	48 89 e5             	mov    rbp,rsp
  401272:	48 83 ec 10          	sub    rsp,0x10
  401276:	89 7d fc             	mov    DWORD PTR [rbp-0x4],edi
  401279:	48 8d 05 cc 0d 00 00 	lea    rax,[rip+0xdcc]        # 40204c <_IO_stdin_used+0x4c>
  401280:	48 89 c7             	mov    rdi,rax
  401283:	b8 00 00 00 00       	mov    eax,0x0
  401288:	e8 43 fe ff ff       	call   4010d0 <printf@plt>
  40128d:	90                   	nop
  40128e:	c9                   	leave
  40128f:	c3                   	ret

0000000000401290 <func>:
  401290:	f3 0f 1e fa          	endbr64
  401294:	55                   	push   rbp
  401295:	48 89 e5             	mov    rbp,rsp
  401298:	48 83 ec 20          	sub    rsp,0x20
  40129c:	48 89 7d e8          	mov    QWORD PTR [rbp-0x18],rdi
  4012a0:	48 8b 4d e8          	mov    rcx,QWORD PTR [rbp-0x18]
  4012a4:	48 8d 45 f8          	lea    rax,[rbp-0x8]
  4012a8:	ba 38 00 00 00       	mov    edx,0x38
  4012ad:	48 89 ce             	mov    rsi,rcx
  4012b0:	48 89 c7             	mov    rdi,rax
  4012b3:	e8 38 fe ff ff       	call   4010f0 <memcpy@plt>
  4012b8:	90                   	nop
  4012b9:	c9                   	leave
  4012ba:	c3                   	ret

00000000004012bb <pop_rdi>:
  4012bb:	f3 0f 1e fa          	endbr64
  4012bf:	55                   	push   rbp
  4012c0:	48 89 e5             	mov    rbp,rsp
  4012c3:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
  4012c7:	5f                   	pop    rdi
  4012c8:	c3                   	ret
  4012c9:	90                   	nop
  4012ca:	5d                   	pop    rbp
  4012cb:	c3                   	ret

00000000004012cc <main>:
  4012cc:	f3 0f 1e fa          	endbr64
  4012d0:	55                   	push   rbp
  4012d1:	48 89 e5             	mov    rbp,rsp
  4012d4:	48 81 ec 30 01 00 00 	sub    rsp,0x130
  4012db:	89 bd dc fe ff ff    	mov    DWORD PTR [rbp-0x124],edi
  4012e1:	48 89 b5 d0 fe ff ff 	mov    QWORD PTR [rbp-0x130],rsi
  4012e8:	48 8d 05 7b 0d 00 00 	lea    rax,[rip+0xd7b]        # 40206a <_IO_stdin_used+0x6a>
  4012ef:	48 89 c7             	mov    rdi,rax
  4012f2:	b8 00 00 00 00       	mov    eax,0x0
  4012f7:	e8 d4 fd ff ff       	call   4010d0 <printf@plt>
  4012fc:	83 bd dc fe ff ff 02 	cmp    DWORD PTR [rbp-0x124],0x2
  401303:	74 32                	je     401337 <main+0x6b>
  401305:	48 8b 85 d0 fe ff ff 	mov    rax,QWORD PTR [rbp-0x130]
  40130c:	48 8b 10             	mov    rdx,QWORD PTR [rax]
  40130f:	48 8b 05 4a 2d 00 00 	mov    rax,QWORD PTR [rip+0x2d4a]        # 404060 <stderr@GLIBC_2.2.5>
  401316:	48 8d 0d 5f 0d 00 00 	lea    rcx,[rip+0xd5f]        # 40207c <_IO_stdin_used+0x7c>
  40131d:	48 89 ce             	mov    rsi,rcx
  401320:	48 89 c7             	mov    rdi,rax
  401323:	b8 00 00 00 00       	mov    eax,0x0
  401328:	e8 b3 fd ff ff       	call   4010e0 <fprintf@plt>
  40132d:	b8 01 00 00 00       	mov    eax,0x1
  401332:	e9 e7 00 00 00       	jmp    40141e <main+0x152>
  401337:	48 8b 85 d0 fe ff ff 	mov    rax,QWORD PTR [rbp-0x130]
  40133e:	48 83 c0 08          	add    rax,0x8
  401342:	48 8b 00             	mov    rax,QWORD PTR [rax]
  401345:	48 8d 15 42 0d 00 00 	lea    rdx,[rip+0xd42]        # 40208e <_IO_stdin_used+0x8e>
  40134c:	48 89 d6             	mov    rsi,rdx
  40134f:	48 89 c7             	mov    rdi,rax
  401352:	e8 a9 fd ff ff       	call   401100 <fopen@plt>
  401357:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  40135b:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
  401360:	75 19                	jne    40137b <main+0xaf>
  401362:	48 8d 05 27 0d 00 00 	lea    rax,[rip+0xd27]        # 402090 <_IO_stdin_used+0x90>
  401369:	48 89 c7             	mov    rdi,rax
  40136c:	e8 9f fd ff ff       	call   401110 <perror@plt>
  401371:	b8 01 00 00 00       	mov    eax,0x1
  401376:	e9 a3 00 00 00       	jmp    40141e <main+0x152>
  40137b:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
  40137f:	48 8d 85 e0 fe ff ff 	lea    rax,[rbp-0x120]
  401386:	48 89 d1             	mov    rcx,rdx
  401389:	ba 00 01 00 00       	mov    edx,0x100
  40138e:	be 01 00 00 00       	mov    esi,0x1
  401393:	48 89 c7             	mov    rdi,rax
  401396:	e8 15 fd ff ff       	call   4010b0 <fread@plt>
  40139b:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
  40139f:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
  4013a4:	75 22                	jne    4013c8 <main+0xfc>
  4013a6:	48 8d 05 e9 0c 00 00 	lea    rax,[rip+0xce9]        # 402096 <_IO_stdin_used+0x96>
  4013ad:	48 89 c7             	mov    rdi,rax
  4013b0:	e8 5b fd ff ff       	call   401110 <perror@plt>
  4013b5:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  4013b9:	48 89 c7             	mov    rdi,rax
  4013bc:	e8 ff fc ff ff       	call   4010c0 <fclose@plt>
  4013c1:	b8 01 00 00 00       	mov    eax,0x1
  4013c6:	eb 56                	jmp    40141e <main+0x152>
  4013c8:	48 8d 95 e0 fe ff ff 	lea    rdx,[rbp-0x120]
  4013cf:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
  4013d3:	48 01 d0             	add    rax,rdx
  4013d6:	c6 00 00             	mov    BYTE PTR [rax],0x0
  4013d9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  4013dd:	48 89 c7             	mov    rdi,rax
  4013e0:	e8 db fc ff ff       	call   4010c0 <fclose@plt>
  4013e5:	c7 45 ec 01 00 00 00 	mov    DWORD PTR [rbp-0x14],0x1
  4013ec:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
  4013ef:	89 c7                	mov    edi,eax
  4013f1:	e8 74 fe ff ff       	call   40126a <fucc>
  4013f6:	48 8d 85 e0 fe ff ff 	lea    rax,[rbp-0x120]
  4013fd:	48 89 c7             	mov    rdi,rax
  401400:	e8 8b fe ff ff       	call   401290 <func>
  401405:	48 8d 05 90 0c 00 00 	lea    rax,[rip+0xc90]        # 40209c <_IO_stdin_used+0x9c>
  40140c:	48 89 c7             	mov    rdi,rax
  40140f:	b8 00 00 00 00       	mov    eax,0x0
  401414:	e8 b7 fc ff ff       	call   4010d0 <printf@plt>
  401419:	b8 00 00 00 00       	mov    eax,0x0
  40141e:	c9                   	leave
  40141f:	c3                   	ret

Disassembly of section .fini:

0000000000401420 <_fini>:
  401420:	f3 0f 1e fa          	endbr64
  401424:	48 83 ec 08          	sub    rsp,0x8
  401428:	48 83 c4 08          	add    rsp,0x8
  40142c:	c3                   	ret
