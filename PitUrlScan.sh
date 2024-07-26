#!/bin/bash
function rate_limiting()		##rate limit check func.   se ci sono tante righe vuol dire tanti errori  -> il sito ci ha bloccati dopo un po'
		{
		status_code=$1 # $1 = status code
			
		if [ "$status_code" -eq 404 ]; then
		    
            result=$(ffuf -w first500.txt  -t 30 -u "$line/FUZZ" -s | wc -l)
		elif [ "$status_code" -eq 403 ]; then
		    
		    result=$(ffuf -w first500.txt -mc 200-299,301,302,307,401,404,405,500 -t 30 -u "$line/FUZZ" -s -maxtime 120 | wc -l)

		elif [ "$status_code" -eq 200 ]; then
		    
            result=$(ffuf -w first500.txt -mc 201-299,301,302,307,401,403,404,405,500 -t 30 -u "$line/FUZZ"  -s  -maxtime 120  | wc -l)	

		elif [ "$status_code" -eq 301 ]; then
		    
		    result=$(ffuf -w first500.txt -mc 200-299,404,302,307,401,403,405,500 -t 30 -u "$line/FUZZ" -s -maxtime 120  | wc -l)
		    
		elif [ "$status_code" -eq 302 ]; then
		    
		    result=$(ffuf -w first500.txt -mc 200-299,404,301,307,401,403,405,500 -t 30 -u "$line/FUZZ"  -s -maxtime 120  | wc -l)
		fi
		echo $result
		}



# Verifica se la directory out esiste, altrimenti la crea
mkdir -p out

# Pulisce il file Output.txt
echo "" > out/Output.txt
Status=""

# Legge le URL dal file urls.txt
while read -r line; do
    echo ""
    echo ""
    echo ""
    echo "--------------Checking Standard status Code Response on $line  -----------"
    echo "wfuzz --conn-delay 2 --req-delay 2 -z list,TestIdonotexist3142-test.php-test.html-test.test-test-GAGAIdoNotExist $line/FUZZ"
    firstfuzz=$(wfuzz --conn-delay 2 --req-delay 2 -z list,TestIdonotexist3142-test.php-test.html-test.test-test-GAGAIdoNotExist $line/FUZZ | grep "Ch" | grep -v "Chars" | cut -d ' ' -f 4)
    echo "check response lenght"
    chars_in_result=$(wfuzz --conn-delay 2 --req-delay 2 -z list,TestIdonotexist3142 $line/FUZZ | grep "Ch" | grep -v "Chars" | cut -d 'W' -f 2 | cut -d 'C' -f 1 | tr -d '\t' | xargs | tr -d ' ' | sed 's/\x1b\[[0-9;]*m//g') 

    echo "Questo è quello fuzzato:"
    echo "$firstfuzz"
    echo ""
    
    c=0
    ecc=0
    while IFS= read -r riga; do
    if [ $c -eq 0 ]; then
        Status=$riga
    elif [ "$riga" -ne "$Status" ]; then
        echo "++ ECCEZIONE, i risultati non sono congruenti"
        ecc=1
    fi
    c=$((c + 1))
done <<< "$firstfuzz"
	echo "++ i risultati sono congruenti"
	
	#echo "++++++ ecc = $ecc"
    if [ $ecc -eq 1 ]; then
        echo "++ lo status code non è stato verificato $line verrà inserito nell'elenco da controllare manualmente"
        echo "$line" >> ManualCheck.txt
    elif [[ -n "$Status" && "$Status" =~ ^[0-9]+$ ]]; then
    	echo "++ lo status code è valido"
    	echo ""
    	

	
		
		
	    # Controllo rate limiting
	    echo "--------- CHECKING Rate Limiting... --------"
	    
	    result=$(rate_limiting $Status)	
	    echo "++++++++++++++ DEBUGGING, Result = $result"

	    if [[ "$result" == *"[WARN]"* ]]; then
	    	echo "++ Il sito non risponde abbastanza in fretta"
		echo "++ L'indirizzo verrà segnato nell'elenco di url lenti --> out/SlowScan.txt"
	    	echo "$line" >> out/SlowScan.txt
	    elif [ $result -gt 80 ]; then
		echo "++ Il sito ci ha bloccati o qualcosa è andato storto"
		echo "++ L'indirizzo verrà segnato nell'elenco di url lenti --> out/SlowScan.txt"
		echo "$line" >> out/SlowScan.txt
		
		
		##			##
		##	SCANSIONE	##
		##			##
		
	    else
		risultato_scansione=""
		echo "++ Il sito sembra comportarsi in modo regolare"
		echo "OOOOOO-  Procedo con la scansione completa con 20 thread differenti"
		echo ""
		#echo "++ STATUS =  $Status"
		if [ "$Status" -eq 404 ]; then
		    echo "++ Filtro risultati per errore $Status"
		    echo "wfuzz -t 20 --hc 404 -w BlindDiscovery.txt -u $line/FUZZ -f temp,raw)"
		    wfuzz -t 20 --hc 404 -w BlindDiscovery.txt -u $line/FUZZ -f temp,raw
		elif [ "$Status" -eq 403 ]; then
		    echo "++ Filtro risultati per errore $Status"
		    echo "wfuzz -t 20 --hc 403 --sc 404,200,301,302,415,429 -z file,BlindDiscovery.txt -u $line/FUZZ -f temp,raw"
		    wfuzz -t 20 --hc 403 --sc 404,200,301,302,415 -w BlindDiscovery.txt -u $line/FUZZ -f temp,raw
		    
		elif [ "$Status" -eq 200 ]; then
		    echo "++ Filtro risultati per numero caratteri. Status = $Status"
		    echo "wfuzz -t 20 --hh $chars_in_result  -w BlindDiscovery.txt -u $line/FUZZ -f temp,raw"
		    wfuzz -t 20 --hh $chars_in_result  -w BlindDiscovery.txt -u $line/FUZZ -f temp,raw
		    
		elif [ "$Status" -eq 301 ]; then
		    echo "++ 301: Filtro risultati per numero caratteri. Status = $Status"
		    #echo "++ Chars = $chars_in_result"
		    echo "wfuzz -t 20 --hh $chars_in_result -w BlindDiscovery.txt -u $line/FUZZ -f temp,raw"
		    wfuzz -t 20 --hh $chars_in_result -w BlindDiscovery.txt -u $line/FUZZ -f temp,raw
		    
		elif [ "$Status" -eq 302 ]; then
		    echo "++ 302: Filtro risultati per numero caratteri. Status = $Status"
		    echo "++ Line = $line"
		    
		    #echo "++ Chars = $chars_in_result"
		    
		    echo "-----COMANDO: wfuzz -t 20 --hh  $chars_in_result -w BlindDiscovery.txt $line/FUZZ -f temp,raw"
		    #risultato_scansione=$()
		    wfuzz -t 20 --hh  $chars_in_result -w BlindDiscovery.txt -u $line/FUZZ -f temp,raw


		else
	            echo "Status Code NON ricunosciuto > slowscan"
	            echo "$line" >> out/SlowScan.txt
		fi
		
		
		
		
		echo ""
		echo "__________________________________________________________"
		echo ""
		#echo "$risultato_scansione"
		echo "" >> out/Output.txt
		echo "$line  StandardStatus= $Status   chars_in_result= $chars_in_result" >> out/Output.txt
		
		cat temp | grep "Ch" | grep -v "Chars" >> out/Output.txt     ######################### NON FUNZIONA
		echo "######################### Ho fatto: cat temp.txt  >> out/Output.txt "

		#echo "" > temp.txt
		
	    fi
	fi
done < urls.txt
