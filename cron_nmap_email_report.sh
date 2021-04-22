#!/usr/bin/env bash
if [[ -z "$1" ]]; then
 echo "No config file. Usage - ahs_linode_nmap_wrapper.sh <conf file>"
 break
fi

declare targ_type=""
declare -a target_list
declare -a target_ip
declare scan_type=""
declare -a port_setting                                                                                                                                                                                                                      declare -a svc_ver
declare -a scrpt_type                                                                                                                                                                                                                        declare -a email_rcpts
declare -a email_sub

while read w_line;
    do
        #echo ${w_line:0:1}
        #echo ${w_line%=*}
        #echo "$w_line"
        if [[ ${w_line:0:1} == "#" ]]; then
            continue
        elif [[ ${w_line%=*} == "TARGETS" ]]; then
            targ_check=${w_line##*=}
            if [[ ${targ_check:0:4} == "/usr" ]]; then
                targ_type="list"
                target_list=( $(ls -d ${w_line##*=}) )
                #echo ${wrapper_cmd[targ_type]}                                                                                                                                                                                                              #echo ${target_list[@]}
            elif [[ ${targ_check:0:1} -ge 1 ]]; then
                targ_type="ip"
                target_ip=${w_line##*=}
                #echo ${wrapper_cmd[targ_type]}
                #echo $targets
            fi
        elif [[ ${w_line%=*} == "SCAN_TYPE" ]]; then
             #echo ${w_line##*=}
             scan_type=${w_line##*=}
        elif [[ ${w_line%=*} == "PORT_SETTING" ]]; then
             #echo ${w_line##*=}
             port_setting=${w_line##*=}
        elif [[ ${w_line%=*} == "SVC_VER" ]]; then
             #echo ${w_line##*=}
             svc_ver=${w_line##*=}
        elif [[ ${w_line%=*} == "SCRPT_TYPE" ]]; then
             #echo ${w_line##*=}                                                                                                                                                                                                                          scrpt_type=${w_line##*=}
        elif [[ ${w_line%=*} == "EMAIL_RCPTS" ]]; then
             #echo ${w_line##*=}
             email_rcpts=${w_line##*=}
        elif [[ ${w_line%=*} == "EMAIL_SUB" ]]; then
             #echo ${w_line##*=}
             email_sub=${w_line##*=}
        fi
    done < $1

conf_name=${1%.*}
conf_name=${conf_name##*/}
results_path="./result_logs/"
processed_path="./processed_logs/"
base_nmap_cmd="/usr/bin/nmap -v4 -O --max-os-tries 1 -Pn -T4 --open"
main_cmd="${base_nmap_cmd} ${scan_type} ${svc_ver[@]} ${scrpt_type[@]} ${port_setting[@]}"
mail_msg_txt="./mail_msg.txt"
clean_up_results="find ${results_path}*.log -mtime +7 -exec rm {} \;"
clean_up_processed="find ${processed_path}*.log -mtime +7 -exec rm {} \;"

if [[ ${targ_type} == "list" ]]; then
    for dc_i in ${target_list[@]}; # For loop to iterate over different datacenter list.
    do
        data_center_list=${dc_i##*/}
        log_date=$(date +'%d_%m_%YT%H_%M_%S')
        results_file="${conf_name}_${data_center_list}_${log_date}.log"
        rslt_file_cmd="-oN ${results_path}${results_file}"
        processed_log="processed_${conf_name}_${data_center_list}_${log_date}.log"
        full_process=${processed_path}${processed_log}
        dc_trgt_cmd="-iL ${dc_i}"
        list_ranges=$(more $dc_i)

        # Full Nmap command with datacenter list
        nmap_list_cmd="${main_cmd} ${rslt_file_cmd} ${dc_trgt_cmd}"
        eval "${nmap_list_cmd}"
        wait

        # Printing the html header to the process log before being sent by email
        printf "<!DOCTYPE html>
            <html>
                <head>
                    <style>                                                                                                                                                                                                                                          table {
                            padding: 3px;
                            background-color: green;
                            border: 2px solid black;
                            border-spacing: 3px;
                        }
                        td {
                            background-color: #82e0aa;
                            border: 1px solid black;
                            text-align: left;
                        }
                        th {
                            background-color: #2ecc71;
                            border: 1px solid black;
                            text-align: right;
                        }
                    </style>
                </head>                                                                                                                                                                                                                                      <body>
                    <h2>Data Center: %s</h2>
                    <h4>List of IP Ranges:</h4>
                    <p>%s</p>" "${data_center_list}" "${list_ranges}" >> ${full_process}

        # Looking for vuln info in the results
        vuln_process=$(more ${results_path}${results_file} | grep -E "^\|\s|^\|\_" | wc -l)

        # Processing if statement to set up emails
        if [ $vuln_process -gt 0 ]; then
           while read r_line;
               do
                   if [[ ${r_line} =~ "Nmap scan report for" ]]; then
                       echo "<p>" >> ${full_process}
                       echo "<table style="width:100%">" >> ${full_process}
					                          echo "<tr><th>${r_line% for *}</th><td>${r_line##*for }</td></tr>" >> ${full_process}
                   elif [[ ${r_line} =~ "/tcp open" || ${r_line} =~ "/tcp  open" || ${r_line} =~ "/udp open" || ${r_line} =~ "/udp  open" ]]; then
                       echo "<tr><th>Port</th><td>${r_line% open *}</td></tr>" >> ${full_process}
                       echo "<tr><th>Service</th><td>${r_line##*open  }</td></tr>" >> ${full_process}
                   elif [[ ${r_line} =~ "| " ||  ${r_line} =~ "|_" ]]; then
                       echo "<tr><th>Vuln</th><td>${r_line}</td></tr>" >> ${full_process}
                   elif [[ ${r_line} =~ "Device type" ]]; then
                       echo "<tr><th>${r_line%: *}</th><td>${r_line##*: }</td></tr>" >> ${full_process}
                   elif [[ ${r_line} =~ "Aggressive OS guesses" ]]; then
                       echo "<tr><th>${r_line%: *}</th><td>${r_line##*: }</td></tr>" >> ${full_process}
                   elif [[ ${r_line} == "" ]]; then
                       echo "</table>" >> ${full_process}
                       echo "</p>" >> ${full_process}
                   fi
               done < ${results_path}${results_file}
            processed_subject=$(printf "%s - Data Center: %s - FOUND VULNERABILITIES." "${email_sub[@]}" "${data_center_list}")

        elif [ $vuln_process -eq 0 ]; then
            while read r_line;
                do
                    if [[ ${r_line} =~ "Nmap scan report for" ]]; then
                       echo "<p>" >> ${full_process}
                       echo "<table style="width:100%">" >> ${full_process}
                       echo "<tr><th>${r_line% for *}</th><td>${r_line##*for }</td></tr>" >> ${full_process}
                   elif [[ ${r_line} =~ "/tcp open" || ${r_line} =~ "/tcp  open" || ${r_line} =~ "/udp open" || ${r_line} =~ "/udp  open" ]]; then
                       echo "<tr><th>Port</th><td>${r_line% open *}</td></tr>" >> ${full_process}
                       echo "<tr><th>Service</th><td>${r_line##*open  }</td></tr>" >> ${full_process}
                   elif [[ ${r_line} =~ "Device type" ]]; then
                       echo "<tr><th>${r_line%: *}</th><td>${r_line##*: }</td></tr>" >> ${full_process}                                                                                                                                                         elif [[ ${r_line} =~ "Aggressive OS guesses" ]]; then
                       echo "<tr><th>${r_line%: *}</th><td>${r_line##*: }</td></tr>" >> ${full_process}
                   elif [[ ${r_line} == "" ]]; then
                       echo "</table>" >> ${full_process}
                       echo "</p>" >> ${full_process}
                   fi
               done < ${results_path}${results_file}
            processed_subject=$(printf "\"%s - Data Center: %s - NO VULNERABILITIES - OPEN PORTS ONLY.\"" "${email_sub[@]}" "${data_center_list}")
        fi

        # Closing the processed logs so it can be sent via email
        printf "</body>
        </html>" >> ${full_process}

        # Processed log along with the subject and email addresses from the config file come together here and turned into a proper email message
        (
        echo "To: ${email_rcpts[@]}";                                                                                                                                                                                                                echo "MIME-Version: 1.0";
        echo "Subject: ${processed_subject}";
        echo "Content-Type: text/html";
        cat ${full_process};
        ) | /usr/sbin/sendmail -t
    done

elif [[ ${targ_type} == "ip" ]]; then
    log_date=$(date +'%d_%m_%YT%H_%M_%S')
    results_file="${conf_name}_${log_date}.log"
    rslt_file_cmd="-oN ${results_path}${results_file}"
    processed_log="processed_${conf_name}_${log_date}.log"
    full_process=${processed_path}${processed_log}

    # Full Nmap command for targeted ip addresses and CIDR
	    nmap_ip_cmd="${main_cmd} ${rslt_file_cmd} ${target_ip[@]}"
    eval "${nmap_ip_cmd}"
    wait

    # Printing the html header to the process log before being sent by email
    printf "<!DOCTYPE html>
        <html>
            <head>
                <style>
                   table {                                                                                                                                                                                                                                          padding: 3px;
                            background-color: green;                                                                                                                                                                                                                     border: 2px solid black;
                            border-spacing: 3px;
                        }
                        td {
                            background-color: #82e0aa;
                            border: 1px solid black;
                            text-align: left;
                        }
                        th {
                            background-color: #2ecc71;
                            border: 1px solid black;
                            text-align: right;
                        }
                </style>
            </head>
            <body>
                <h2>Target(s): %s</h2>" "${target_ip[@]}" >> ${full_process}

    # Looking for vuln info in the results
    vuln_process=$(more ${results_path}${results_file} | grep -E "^\|\s|^\|\_" | wc -l)

    # Processing if statement to set up emails
    if [ $vuln_process -gt 0 ]; then
        while read r_line;
            do
                if [[ ${r_line} =~ "Nmap scan report for" ]]; then
                    echo "<p>" >> ${full_process}
                    echo "<table style="width:100%">" >> ${full_process}
                    echo "<tr><th>${r_line% for *}</th><td>${r_line##*for }</td></tr>" >> ${full_process}
                elif [[ ${r_line} =~ "/tcp open" || ${r_line} =~ "/tcp  open" || ${r_line} =~ "/udp open" || ${r_line} =~ "/udp  open" ]]; then
                    echo "<tr><th>Port</th><td>${r_line% open *}</td></tr>" >> ${full_process}
                    echo "<tr><th>Service</th><td>${r_line##*open  }</td></tr>" >> ${full_process}
                elif [[ ${r_line} =~ "| " ||  ${r_line} =~ "|_" ]]; then
                    echo "<tr><th>Vuln</th><td>${r_line}</td></tr>" >> ${full_process}
                elif [[ ${r_line} =~ "Device type" ]]; then
                    echo "<tr><th>${r_line%: *}</th><td>${r_line##*: }</td></tr>" >> ${full_process}
                elif [[ ${r_line} =~ "Aggressive OS guesses" ]]; then
                    echo "<tr><th>${r_line%: *}</th><td>${r_line##*: }</td></tr>" >> ${full_process}
                elif [[ ${r_line} == "" ]]; then
                    echo "</table>" >> ${full_process}
                    echo "</p>" >> ${full_process}
                fi
            done < ${results_path}${results_file}
        processed_subject=$(printf "%s - Conf File: %s - FOUND VULNERABILITIES." "${email_sub[@]}" "${conf_name}")

    elif [ $vuln_process -eq 0 ]; then
        while read r_line;
            do
                if [[ ${r_line} =~ "Nmap scan report for" ]]; then
				    echo "<p>" >> ${full_process}
                    echo "<table style="width:100%">" >> ${full_process}
                    echo "<tr><th>${r_line% for *}</th><td>${r_line##*for }</td></tr>" >> ${full_process}
                elif [[ ${r_line} =~ "/tcp open" || ${r_line} =~ "/tcp  open" || ${r_line} =~ "/udp open" || ${r_line} =~ "/udp  open" ]]; then
                    echo "<tr><th>Port</th><td>${r_line% open *}</td></tr>" >> ${full_process}
                    echo "<tr><th>Service</th><td>${r_line##*open  }</td></tr>" >> ${full_process}
                elif [[ ${r_line} =~ "Device type" ]]; then
                    echo "<tr><th>${r_line%: *}</th><td>${r_line##*: }</td></tr>" >> ${full_process}
                elif [[ ${r_line} =~ "Aggressive OS guesses" ]]; then
                    echo "<tr><th>${r_line%: *}</th><td>${r_line##*: }</td></tr>" >> ${full_process}
                elif [[ ${r_line} == "" ]]; then                                                                                                                                                                                                                 echo "</table>" >> ${full_process}
                    echo "</p>" >> ${full_process}                                                                                                                                                                                                           fi
            done < ${results_path}${results_file}
        processed_subject=$(printf "%s - Conf File: %s - NO VULNERABILITIES - OPEN PORTS ONLY." "${email_sub[@]}" "${conf_name}")
    fi

    # Closing the processed logs so it can be sent via email
    printf "</body>
        </html>" >> ${full_process}

    # Processed log along with the subject and email addresses from the config file come together here and turned into a proper email message
    (
    echo "To: ${email_rcpts[@]}";
    echo "MIME-Version: 1.0";
    echo "Subject: ${processed_subject}";
    echo "Content-Type: text/html";
    cat ${full_process};
    ) | /usr/sbin/sendmail -t
fi

eval "${clean_up_processed}"
eval "${clean_up_results}"