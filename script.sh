#!/bin/sh

set -e;

main() {
  . ./library.sh;
  echo "idaig elmegy4";

  test -n "$TRIVY_SUPPRESSION_TREE_PATH";
  echo "idaig elmegy5";
  test -n "$TRIVY_REPORT_PATH";
  echo "idaig elmegy5";
  test -n "$LOG_FILE";
  echo "idaig elmegy6";
  test -n "$REPO_USERNAME";
  echo "idaig elmegy7";
  test -n "$REPO_PASSWORD";
  echo "idaig elmegy8";
  test -n "$DOCKER_TLS_VERIFY";
  echo "idaig elmegy9";
  test -n "$DOCKER_REPO_URI";
  echo "idaig elmegy10";
  echo "ez a docker host elvileg: $DOCKER_HOST";
  test -n "$DOCKER_HOST";
  echo "idaig elmegy11";
  test -n "$DOCKER_HOST_CA";
  echo "idaig elmegy12";
  test -n "$DOCKER_HOST_CERT";
  echo "idaig elmegy13";
  test -n "$DOCKER_HOST_KEY";
  echo "idaig elmegy14";
  mkdir --parents ~/.docker;
  echo "idaig elmegy15";
  echo "$DOCKER_HOST_CA" > ~/.docker/ca.pem;
  echo "$DOCKER_HOST_CERT" > ~/.docker/cert.pem;
  echo "$DOCKER_HOST_KEY" > ~/.docker/key.pem;
  echo "idaig elmegy16";
  # - docker login --username $REPO_USERNAME --password $REPO_PASSWORD $DOCKER_REPO_URI

  # make these paths to absolute paths, so they work global
  TRIVY_SUPPRESSION_TREE_PATH="$(pwd -P)/${TRIVY_SUPPRESSION_TREE_PATH}";
  TRIVY_REPORT_PATH="$(pwd -P)/${TRIVY_REPORT_PATH}";
  CVE_PATH="$(pwd -P)/${CVE_PATH}";
  LOG_FILE="$(pwd -P)/${LOG_FILE}";

  mkdir -p "$TRIVY_REPORT_PATH";
  mkdir -p "$CVE_PATH";

  # Save trivy version for debugging
  trivy --version >> "$LOG_FILE" 2>&1;

  # get image names from all running docker container
  image_names=$(docker ps --format '{{.Image}}');
  process_images "$image_names";

  ( cd src || return ; PYTHONPATH="$PWD" python3 security/cveticket/cveTickets.py );
  ( cd src || return ; PYTHONPATH="$PWD" python3 security/componentticket/componentTickets.py );

  post_script;
  console_log_simple "${APP_NAME} finished";
}

normalize_image_name() {
  # Delete ports and replace ":" and "@" with "/"
  echo "$1" | sed 's/:[[:digit:]]\+\//\//g' | sed 's/:/\//g' | sed 's/@/\//g'; # return value
}

process_images() {
    # global count of images
    max_count=$(echo "$1" | wc -w);
    count=0;

    # loop through all active images
    for image in $1
    do
      count=$((count+1));
      DOCKER_FALLBACK=0;
      fullPath="$image"; # for libraries log function
      # image_with_digest=$(docker inspect --format '{{index .RepoDigests 0}}' $image);
      # digest_count=$(docker inspect --format '{{len .RepoDigests}}' $image);
      # log "Details: digest $image_with_digest out of $digest_count";

      # use suppression tree for ignoring images
      tree="${TRIVY_SUPPRESSION_TREE_PATH}/$(normalize_image_name "$fullPath")";
      while [ "${tree}" != "$(dirname "${TRIVY_SUPPRESSION_TREE_PATH}")" ] && [ "${tree}" != "." ] && [ "${tree}" != "/" ] && [ -n "${tree}" ] ; do
        filename="${tree}/.exclude"
        if [ -f "${filename}" ]; then
          console_log "Skip because file ${filename} found";
          continue 2; # Continue at loop on 2nd level, that is "outer loop".
        fi;
        tree="$(dirname "${tree}")";
      done;

      image_base_name="$(basename "$image")";
      pull_image="";
      if [ -n "${image_base_name##*:*}" ]; then
        log "Found image without tag - check with docker inspect";
        repotags_count="$(docker inspect --format '{{len .RepoTags}}' "$image")";
        if [ "$repotags_count" -gt "0" ]; then
          image="$(docker inspect --format '{{index .RepoTags 0}}' "$image")";
          fullPath="$image"; # for libraries log function
          log "$repotags_count RepoTags found. Use it from now on.";
        else # Special case, when only digests are available
          repodigests_count="$(docker inspect --format '{{len .RepoDigests}}' "$image")";
          if [ "$repodigests_count" -gt "0" ]; then
            image="$(docker inspect --format '{{index .RepoDigests 0}}' "$image")";
            fullPath="$image"; # for libraries log function
            pull_image="$(docker inspect --format '{{.Id}}' "$image")";
            log "$repodigests_count RepoDigests found. Use it from now on as image and Id for pulling.";
          else
            image="$(docker inspect --format '{{.Id}}' "$image")";
            fullPath="$image"; # for libraries log function
            log "No RepoTags found. Use imageId from now on. See LOG_FILE for more information.";
            docker inspect "$image" >> "$LOG_FILE" 2>&1;
          fi;
        fi;
      fi;

      if [ -z "${pull_image}" ]; then
        pull_image="$image"
      fi;

      dest_directory="$TRIVY_REPORT_PATH/$(normalize_image_name "$pull_image")";
      if [ -d "${dest_directory}" ]; then
        console_log "Skip because an image with this normalized name was already scanned.";
        continue;
      fi;

      mkdir -p "$dest_directory";
      log "Begin with skopeo";
      skopeo copy --src-daemon-host "$DOCKER_HOST" --src-tls-verify="$DOCKER_TLS_VERIFY" --src-cert-dir ~/.docker/ \
        "$(if [ "${DOCKER_FALLBACK}" -eq "1" ]; then echo "docker:$pull_image"; else echo "docker-daemon:$pull_image"; fi;)" \
        "oci:$dest_directory" >> "$LOG_FILE" 2>&1;
      if [ "$(ls -A "${dest_directory}" | wc -l)" != "3" ]; then
        log "Warning. Count files/dirs in oci-image directory: $(ls -A "${dest_directory}" | wc -l)";
      fi;
      log "Begin with trivy";
      trivy image --timeout 15m --clear-cache >> "$LOG_FILE" 2>&1;
      trivy image --timeout 15m -f json -o "$dest_directory/scan_result.json" --input "$dest_directory" >> "$LOG_FILE" 2>&1 || touch "$dest_directory/scan_failed";

      if [ -f "$dest_directory/scan_failed" ]; then
        echo "Vulnerabilities found!";
        save_cve;
      fi;
    done;
}

post_script() {
  if [ -n "${MAX_ARTIFACT_SIZE}" ]; then
    # make sure, du is not running without parameters.
    run \
      "test -n \"$TRIVY_REPORT_PATH\" && test -n \"$CVE_PATH\" && test -n \"$LOG_FILE\"" \
      "Internal Error in post_script: first assertion failed";

    run \
      "test -d \"$TRIVY_REPORT_PATH/\" && test -d \"$CVE_PATH/\" && test -f \"$LOG_FILE\"" \
      "Internal Error in post_script: second assertion failed";

    size="$(du -csm "$TRIVY_REPORT_PATH" "$CVE_PATH" "$LOG_FILE" "src/notification.log" | tail -1 | grep -Po '\d*')" || { echo "Size calculation failed" && size="0"; };
    if [ "$size" -gt "$MAX_ARTIFACT_SIZE" ]; then
      echo "Artifacts too big ($size MB), pass only log $LOG_FILE and $CVE_PATH";
      find "$TRIVY_REPORT_PATH" -mindepth 1 -delete; # delete all files in reports directory
    fi;
  fi;
}

main;