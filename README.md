# amcache-vt
pulls sha-1 hashes from windows amcache, queries virus total to see if hashes are associated with malicious executables

requirements:
```commandline
virustotal3
regipy
termcolor
tqdm
```
## usage:
```
%> amcache-vt.py [-h] -f AMCACHE -o OUTPUT [-l LIMIT]

options:
   -h, --help : show this help message and exit

   -f AMCACHE, --amcache AMCACHE  amcache file to parse
 
   -o OUTPUT, --output OUTPUT output file name 

-l LIMIT, --limit LIMIT limit the number of queries

```
Examples:
   - Testing (limits to 20 queries):  python amcache-vt.py -f ./Amcache.hve -o './test2.csv' -l 20
   - Processes whole file: python amcache-vt.py -f ./Amcache.hve -o './test2.csv'

Output:

To Screen:
```
[+] Amcache Results
   ========================
   [Harmless/Malicious Votes] :  concensus : filepath : sha1
   ========================
   [H:0 / M:0] : unknown : c:\program files (x86)\atlassian\sourcetree\DeltaCompressionDotNet.PatchApi.dll : 7b8f029ac5ade3af79a773b6430cca032254a216
   [H:5 / M:0] : harmless : c:\program files (x86)\atlassian\sourcetree\Askpass.exe : c9d6ff2c88cd424114c2a15b18746a387a698403
   [H:0 / M:0] : unknown : c:\program files (x86)\atlassian\sourcetree\tools\putty\puttygen.exe : 1bb6c046be39b9ee3ec541a0639dcbaad232498a
   [H:0 / M:0] : unknown : c:\program files (x86)\atlassian\sourcetree\Atlassian.FastTree.dll : c0f251b1f95b3a1f1b8c5e9eacbed94a69193af1
   [H:3 / M:28] : malicious : c:\program files (x86)\atlassian\sourcetree\Atlassian.PathTrimmingTextBlock.dll : 93693613834f29b19cb1085bfa178e84b250438d
   [H:0 / M:0] : unknown : c:\program files (x86)\atlassian\sourcetree\DeltaCompressionDotNet.dll : 5640446431fc994cec816475bbeaaecdc650d99a
   -------------------------
[+] Results of: ./Amcache.hve saved to: ./test2.csv
```

To File:
```
timestamp,last_modified_timestamp,sha1,full_path,harmless,malicious,consensus,
2022-11-03T08:02:44.737096+00:00,,d9365a05fe38babc538b4ff029adb0865eb02686,,0,0,unknown
2022-04-21T12:43:41.501558+00:00,,36cd11808879cc611d5133a90cc0d70ffb7be578,,0,0,unknown
2022-04-19T15:26:42.426920+00:00,,1b3846b00a121040b4a4b2796773ef90899f6048,,5,0,harmless
2022-04-19T09:30:36.857456+00:00,,0158e9d6a75a2b13737ce049329c9de42a4791ea,,0,0,unknown
2022-04-21T12:43:40.423650+00:00,,f29843a8bb694032011d6ed7c76ea133718cdb26,,0,0,unknown
2022-04-21T12:43:41.142262+00:00,,af18147377193d2ec3eea2508e136c7f8e4c78d0,,0,0,unknown
2022-04-21T12:43:41.142262+00:00,,ded4fea87693cb61d9ec49eaf914632724d4fb2e,,0,0,unknown
2022-04-21T12:43:41.157882+00:00,,6509389c8ede0927098f16297e00655165ea25ac,,0,1,malicious
```