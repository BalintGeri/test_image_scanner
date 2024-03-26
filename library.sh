#!/bin/sh

test -n "$APP_NAME";
test -n "$LOG_FILE";

save_cve() {
  test -n "$TRIVY_REPORT_PATH";
  test -n "$CVE_PATH";
  test -n "$CI_JOB_URL";
  test -n "$dest_directory";
  test -n "$image";

  json_report_file="$dest_directory/scan_result.json";
  if [ -f "$json_report_file" ]; then
    filtered_vulnerabilities="$(
      jq '.Results[].Vulnerabilities[]? | select( .Severity == ("HIGH", "CRITICAL") )' \
        "$json_report_file"
    )";

    # Iterate through all filtered vulnerabilities
    # Since for-loop is splitting on spaces, gsub is needed
    for data in $(echo "$filtered_vulnerabilities" | jq -c '(.. | strings) |= gsub(" ";"&#20;")'); do
      data="$(echo "$data" | jq -r '(.. | strings) |= gsub("&#20;";" ")')";
      name="$(echo "$data" | jq -r '.VulnerabilityID')";
      description="$(echo "$data" | jq -r '.Description')";
      url="$(echo "$data" | jq -r '.PrimaryURL')";
      severity="$(echo "$data" | jq -r '.Severity')";

      componentName="$(echo "$data" | jq -r '.PkgPath // empty')";
      if [ -z "$componentName" ]; then
        componentName="$(echo "$data" | jq -r '.PkgID // empty')";
      fi;
      if [ -z "$componentName" ]; then
        componentName="$(echo "$data" | jq -r '.PkgName')@$(echo "$data" | jq -r '.InstalledVersion')";
      fi;
      src="Image: $image";
      fixedVersion="$(echo "$data" | jq -r '.FixedVersion // empty')";
      if [ -n "$fixedVersion" ]; then
        suggestion="Please update/downgrade to $fixedVersion";
      else
        suggestion="";
      fi;

      if [ "sha256:" = "$(echo "$image" | cut -c -7)" ]; then
        imagePath="$image";
        version="";
      else
        imagePath="$(echo "$image" | rev | cut -d: -f2- | rev)";
        version="$(echo "$image" | rev | cut -d: -f1 | rev)";

        run \
          "test \"$image\" = \"$imagePath:$version\"" \
          "Internal Error: Splitting image string failed";
      fi;
      part_dest_directory="$(echo "$dest_directory" | cut -d'/' -f5-)";
      urlReport="$CI_JOB_URL/artifacts/raw/$part_dest_directory/scan_result.json";
      log "$severity vulnerability with name $name found! Save it for notification step";

      cve_report_file="$CVE_PATH/$name.json";
      if [ -f "$cve_report_file" ]; then
        jq --arg componentName "$componentName" --arg imagePath "$imagePath" --arg src "$src" \
        --arg version "$version" --arg urlReport "$urlReport" --arg suggestion "$suggestion" \
        '.components += [{name: $componentName, fullPath: $imagePath, src: $src,
        version: $version, urlReport: $urlReport, suggestion: $suggestion}]' \
        "$cve_report_file" > tmpfile && mv tmpfile "$cve_report_file";
      else
        jq -n --arg name "$name" --arg description "$description" --arg url "$url" --arg severity "$severity" \
        --arg componentName "$componentName" --arg imagePath "$imagePath" --arg src "$src" \
        --arg version "$version" --arg urlReport "$urlReport" --arg suggestion "$suggestion" \
        '{name: $name, description: $description, url: $url, severity: $severity,
        components: [{name: $componentName, fullPath: $imagePath, src: $src,
        version: $version, urlReport: $urlReport, suggestion: $suggestion}]}' > "$cve_report_file";
      fi;
    done;
  fi;
}

console_log_simple() {
  echo "[$APP_NAME] $*";
}

console_log() {
  test -n "$fullPath";
  test -n "$count";
  test -n "$max_count";
  echo "[$APP_NAME][${count}/${max_count}][$fullPath]$(if [ -n "${EXTRA_ECHO}" ]; then echo "[${EXTRA_ECHO}]";fi) $*";
}

log() {
  test -n "$fullPath";
  test -n "$count";
  test -n "$max_count";
  echo "[$APP_NAME][${count}/${max_count}][$fullPath]$(if [ -n "${EXTRA_ECHO}" ]; then echo "[${EXTRA_ECHO}]";fi) \
[$(date +%H:%M:%S)] $*" | tee -a "${LOG_FILE}";
}

run_failsafe() {
  eval "$1" || (log "$2");
}

run_timeout() {
  # BusyBox v1.35.0 timeout executable returns 143 error code on timeout / GNU coreutils returns 124 error code on timeout
  eval timeout "$1" "$2" || (
    retVal=$? && ([ $retVal -ne 143 ] || echo "Timeout after $1!") && log "$3" && exit $retVal
  );
}

run() {
  eval "$1" || (log "$2" && exit 1);
}