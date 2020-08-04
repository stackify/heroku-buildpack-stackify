#!/usr/bin/env bash

readonly STACKIFY_HOME="${HOME}/.dpkg/usr/local/stackify"
readonly CONFIG_FILE="${STACKIFY_HOME}/stackify-agent/stackify-agent.conf"
readonly STACKIFY_INSTALL_PATH="${STACKIFY_HOME}"
readonly STACKIFY_AGENT_INSTALL_PATH="${STACKIFY_HOME}/stackify-agent"
readonly STACKIFY_JAVA_EXEC="${STACKIFY_INSTALL_PATH}/.java/amd64/bin/java"
readonly STACKIFY_JAVA_OPTS="-XX:+UseSerialGC -Xmx192m"
readonly STACKIFY_JAVA_JAR="${STACKIFY_AGENT_INSTALL_PATH}/stackify-agent.jar"
readonly STACKIFY_JAVA_MAIN_CLASS="com.stackify.agent.AgentMain";
readonly STACKIFY_AGENT_LOG="${STACKIFY_AGENT_INSTALL_PATH}/log/stackify-agent.log"
readonly STACKIFY_HEROKU_LOCK_FILE="${STACKIFY_AGENT_INSTALL_PATH}/stackify-heroku.lock"

# update stackify-agent configuration
sed -i 's:^[ \t]*sudoDisabled[ \t]*=\([ \t]*.*\)$:sudoDisabled=true:' ${CONFIG_FILE}
sed -i 's:^[ \t]*containerized[ \t]*=\([ \t]*.*\)$:containerized=true:' ${CONFIG_FILE}

if [ ! -z "$STACKIFY_KEY" ]; then
    echo "STACKIFY_KEY: ${STACKIFY_KEY}"
    sed -i 's:^[ \t]*activationKey[ \t]*=\([ \t]*.*\)$:activationKey='\"${STACKIFY_KEY}\"':' ${CONFIG_FILE}
fi

if [ ! -z "$STACKIFY_APPLICATION_NAME" ]; then
    echo "STACKIFY_APPLICATION_NAME: ${STACKIFY_APPLICATION_NAME}"
    sed -i 's:^[ \t]*deviceAlias[ \t]*=\([ \t]*.*\)$:deviceAlias='\""${STACKIFY_APPLICATION_NAME}"\"':' ${CONFIG_FILE}
fi

if [ ! -z "$STACKIFY_ENVIRONMENT_NAME" ]; then
    echo "STACKIFY_ENV: ${STACKIFY_ENVIRONMENT_NAME}"
    sed -i 's:^[ \t]*environment[ \t]*=\([ \t]*.*\)$:environment='\""${STACKIFY_ENVIRONMENT_NAME}"\"':' ${CONFIG_FILE}
fi

# do not let JAVA_TOOL_OPTIONS slip in (as the JVM does by default)
if [ ! -z "$JAVA_TOOL_OPTIONS" ]; then
    echo "warning: ignoring JAVA_TOOL_OPTIONS=$JAVA_TOOL_OPTIONS"
    unset JAVA_TOOL_OPTIONS
fi

# set all profilers to use HTTP transport
export STACKIFY_TRANSPORT="agent_http"

# start Stackify Linux Agent in background
export STACKIFY_ROOT_FOLDER="${STACKIFY_HOME}"
cd $STACKIFY_AGENT_INSTALL_PATH

# start if no lock file is present
if [ ! -f "$STACKIFY_HEROKU_LOCK_FILE" ]; then
    nohup $STACKIFY_JAVA_EXEC $STACKIFY_JAVA_OPTS -cp $STACKIFY_JAVA_JAR $STACKIFY_JAVA_MAIN_CLASS &
    touch $STACKIFY_HEROKU_LOCK_FILE
fi

# set back to home directory
cd $HOME
