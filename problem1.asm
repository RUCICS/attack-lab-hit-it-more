
problem1:     file format elf64-x86-64


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

00000000004010b0 <strcpy@plt>:
  4010b0:	f3 0f 1e fa          	endbr64
  4010b4:	ff 25 46 2f 00 00    	jmp    QWORD PTR [rip+0x2f46]        # 404000 <strcpy@GLIBC_2.2.5>
  4010ba:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

00000000004010c0 <puts@plt>:
  4010c0:	f3 0f 1e fa          	endbr64
  4010c4:	ff 25 3e 2f 00 00    	jmp    QWORD PTR [rip+0x2f3e]        # 404008 <puts@GLIBC_2.2.5>
  4010ca:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

00000000004010d0 <fread@plt>:
  4010d0:	f3 0f 1e fa          	endbr64
  4010d4:	ff 25 36 2f 00 00    	jmp    QWORD PTR [rip+0x2f36]        # 404010 <fread@GLIBC_2.2.5>
  4010da:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

00000000004010e0 <fclose@plt>:
  4010e0:	f3 0f 1e fa          	endbr64
  4010e4:	ff 25 2e 2f 00 00    	jmp    QWORD PTR [rip+0x2f2e]        # 404018 <fclose@GLIBC_2.2.5>
  4010ea:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

00000000004010f0 <fprintf@plt>:
  4010f0:	f3 0f 1e fa          	endbr64
  4010f4:	ff 25 26 2f 00 00    	jmp    QWORD PTR [rip+0x2f26]        # 404020 <fprintf@GLIBC_2.2.5>
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
  401148:	48 c7 c7 58 12 40 00 	mov    rdi,0x401258
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

0000000000401216 <func1>:
  401216:	f3 0f 1e fa          	endbr64
  40121a:	55                   	push   rbp
  40121b:	48 89 e5             	mov    rbp,rsp
  40121e:	bf 04 20 40 00       	mov    edi,0x402004
  401223:	e8 98 fe ff ff       	call   4010c0 <puts@plt>
  401228:	bf 00 00 00 00       	mov    edi,0x0
  40122d:	e8 ee fe ff ff       	call   401120 <exit@plt>

0000000000401232 <func>:
  401232:	f3 0f 1e fa          	endbr64
  401236:	55                   	push   rbp
  401237:	48 89 e5             	mov    rbp,rsp
  40123a:	48 83 ec 20          	sub    rsp,0x20
  40123e:	48 89 7d e8          	mov    QWORD PTR [rbp-0x18],rdi
  401242:	48 8b 55 e8          	mov    rdx,QWORD PTR [rbp-0x18]
  401246:	48 8d 45 f8          	lea    rax,[rbp-0x8]
  40124a:	48 89 d6             	mov    rsi,rdx
  40124d:	48 89 c7             	mov    rdi,rax
  401250:	e8 5b fe ff ff       	call   4010b0 <strcpy@plt>
  401255:	90                   	nop
  401256:	c9                   	leave
  401257:	c3                   	ret

0000000000401258 <main>:
  401258:	f3 0f 1e fa          	endbr64
  40125c:	55                   	push   rbp
  40125d:	48 89 e5             	mov    rbp,rsp
  401260:	48 81 ec 20 01 00 00 	sub    rsp,0x120
  401267:	89 bd ec fe ff ff    	mov    DWORD PTR [rbp-0x114],edi
  40126d:	48 89 b5 e0 fe ff ff 	mov    QWORD PTR [rbp-0x120],rsi
  401274:	bf 14 20 40 00       	mov    edi,0x402014
  401279:	e8 42 fe ff ff       	call   4010c0 <puts@plt>  # 输出 Do you like ICS?
  40127e:	83 bd ec fe ff ff 02 	cmp    DWORD PTR [rbp-0x114],0x2
  401285:	74 2d                	je     4012b4 <main+0x5c>
  401287:	48 8b 85 e0 fe ff ff 	mov    rax,QWORD PTR [rbp-0x120]
  40128e:	48 8b 10             	mov    rdx,QWORD PTR [rax]
  401291:	48 8b 05 c8 2d 00 00 	mov    rax,QWORD PTR [rip+0x2dc8]        # 404060 <stderr@GLIBC_2.2.5>
  401298:	be 25 20 40 00       	mov    esi,0x402025
  40129d:	48 89 c7             	mov    rdi,rax
  4012a0:	b8 00 00 00 00       	mov    eax,0x0
  4012a5:	e8 46 fe ff ff       	call   4010f0 <fprintf@plt>
  4012aa:	b8 01 00 00 00       	mov    eax,0x1
  4012af:	e9 bd 00 00 00       	jmp    401371 <main+0x119>
  4012b4:	48 8b 85 e0 fe ff ff 	mov    rax,QWORD PTR [rbp-0x120]
  4012bb:	48 83 c0 08          	add    rax,0x8
  4012bf:	48 8b 00             	mov    rax,QWORD PTR [rax]
  4012c2:	be 37 20 40 00       	mov    esi,0x402037
  4012c7:	48 89 c7             	mov    rdi,rax
  4012ca:	e8 31 fe ff ff       	call   401100 <fopen@plt>
  4012cf:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  4012d3:	48 83 7d f8 00       	cmp    QWORD PTR [rbp-0x8],0x0
  4012d8:	75 14                	jne    4012ee <main+0x96>
  4012da:	bf 39 20 40 00       	mov    edi,0x402039
  4012df:	e8 2c fe ff ff       	call   401110 <perror@plt>
  4012e4:	b8 01 00 00 00       	mov    eax,0x1
  4012e9:	e9 83 00 00 00       	jmp    401371 <main+0x119>
  4012ee:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
  4012f2:	48 8d 85 f0 fe ff ff 	lea    rax,[rbp-0x110]
  4012f9:	48 89 d1             	mov    rcx,rdx
  4012fc:	ba 00 01 00 00       	mov    edx,0x100
  401301:	be 01 00 00 00       	mov    esi,0x1
  401306:	48 89 c7             	mov    rdi,rax
  401309:	e8 c2 fd ff ff       	call   4010d0 <fread@plt>
  40130e:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
  401312:	48 83 7d f0 00       	cmp    QWORD PTR [rbp-0x10],0x0
  401317:	75 1d                	jne    401336 <main+0xde>
  401319:	bf 3f 20 40 00       	mov    edi,0x40203f
  40131e:	e8 ed fd ff ff       	call   401110 <perror@plt>
  401323:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  401327:	48 89 c7             	mov    rdi,rax
  40132a:	e8 b1 fd ff ff       	call   4010e0 <fclose@plt>
  40132f:	b8 01 00 00 00       	mov    eax,0x1
  401334:	eb 3b                	jmp    401371 <main+0x119>
  401336:	48 8d 95 f0 fe ff ff 	lea    rdx,[rbp-0x110]
  40133d:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
  401341:	48 01 d0             	add    rax,rdx
  401344:	c6 00 00             	mov    BYTE PTR [rax],0x0
  401347:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  40134b:	48 89 c7             	mov    rdi,rax
  40134e:	e8 8d fd ff ff       	call   4010e0 <fclose@plt>
  401353:	48 8d 85 f0 fe ff ff 	lea    rax,[rbp-0x110]
  40135a:	48 89 c7             	mov    rdi,rax
  40135d:	e8 d0 fe ff ff       	call   401232 <func>  # 缺陷函数
  401362:	bf 45 20 40 00       	mov    edi,0x402045
  401367:	e8 54 fd ff ff       	call   4010c0 <puts@plt> # 输出函数，替换
  40136c:	b8 00 00 00 00       	mov    eax,0x0
  401371:	c9                   	leave
  401372:	c3                   	ret

Disassembly of section .fini:

0000000000401374 <_fini>:
  401374:	f3 0f 1e fa          	endbr64
  401378:	48 83 ec 08          	sub    rsp,0x8
  40137c:	48 83 c4 08          	add    rsp,0x8
  401380:	c3                   	ret
