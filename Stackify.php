<?php

namespace Stackify\Util;

/**
 * Provides a static method to call functions synchronously using lockfiles.
 */
class Sync
{
    /**
     * Default lock file
     */
    public static $lock = '.lock';
    private static $locks = array();

    /**
     * Call a function in a mutually exclusive way using a lockfile.
     * A process will only block other processes and never block itself,
     * so you can safely nest synchronized operations.
     * @throws \Exception
     */
    public static function call($func, $lock = null)
    {
        $lock = self::path($lock);
        // just call function if lock already acquired
        if (isset(self::$locks[$lock])) {
            return $func();
        }
        try {
            // acquire lock
            $handle = fopen($lock, 'w');
            if (!$handle || !flock($handle, LOCK_EX)) {
                throw new \RuntimeException('Unable to lock on "' . $lock . '"');
            }
            self::$locks[$lock] = true;
            // call function and release lock
            $return = $func();
            self::release($lock, $handle);
            return $return;
        } catch (\Exception $e) {
            // release lock and rethrow any exception
            self::release($lock, $handle);
            throw $e;
        }
    }

    /**
     * Get absolute path to a lock file
     */
    public static function path($lock = null)
    {
        if (!isset($lock)) {
            $lock = self::$lock;
        }
        if (!is_file($lock)) {
            touch($lock);
            chmod($lock, 0777);
        }
        return realpath($lock);
    }

    /**
     * Set of already aquired locks
     */
    private static function release($lock, $handle)
    {
        unset(self::$locks[$lock]);
        if ($handle) {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}

namespace Stackify\Profiler;

/**
 * Handles link to PHP Extension.
 * @package Stackify\Profiler
 */
class StackifyExtension
{
    public function getTraceFrames()
    {
        return stackify_get_frames();
    }

    public function watchSpan($function_name, $category)
    {
        return stackify_span_watch($function_name, $category);
    }
}

namespace Stackify;

class Profiler
{
    const MODE_DISABLED = 0;
    const MODE_FULL = 2;

    // default profiler configuration
    public static $defaultOptions = array(
        'ignored_functions' => array(
            'call_user_func',
            'call_user_func_array',
            'array_filter',
            'array_map',
            'array_reduce',
            'array_walk',
            'array_walk_recursive',
            'Symfony\Component\DependencyInjection\Container::get',
        ),
        'exception_function' => null,
        'framework' => null,
        'transaction_functions' => array(),
        'transaction_callback' => null,
        'watches' => array()
    );

    public static $trace;
    private static $stackifyExtension;
    private static $shutdownRegistered = false;
    private static $error = false;
    private static $mode = self::MODE_DISABLED;
    private static $applicationName;
    private static $environmentName;
    private static $transport;
    private static $transportHttpEndpoint;
    private static $exceptions = array();
    private static $transactionName;

    public static $traceMapByParentFrameId;
    private static $max_files = 10;
    private static $logFilePath =  null;
    private static $errorLog = null;
    private static $errorLogFile = null;
    private static $isCli = false;
    private static $logFilePathWritable = null;
    public static $customUrlTransactionName = null;
    public static $hasExecutedTransactionFunction = false;

    /**
     * Custom error handler to log profiler specific errors to stackify log file - to avoid noise in standard php error logging.
     * Only runs when debug is enabled
     */
    public static function stackifyErrorHandler($errno, $errstr, $errfile, $errline) {
        if (self::isDebug()) {
            self::log(1, $errstr . " : " .  $errfile . " : " . $errno . " : " . $errline);
        }
    }

    /**
     * Check if debug mode is enabled on the profiler
     * Checks ini and environment variables
     */
    public static function isDebug() {
        $debug_enabled = strval(ini_get("stackify.debug_enabled"));
        if ($debug_enabled != NULL && $debug_enabled == "1") {
            return true;
        }
        $debug_enabled = strval(getenv('STACKIFY_DEBUG_ENABLED'));
        if ($debug_enabled != NULL && strtoupper($debug_enabled) == "TRUE") {
            return true;
        }
        return false;
    }

    /**
     * Gets the configured track all
     * Checks ini and environment variables
     */
    public static function isTrackAll() {
        $track_all_enabled = strval(ini_get("stackify.track_all_enabled"));
        if ($track_all_enabled != NULL && $track_all_enabled == "1") {
            return true;
        }
        $track_all_enabled = strval(getenv('STACKIFY_TRACK_ALL_ENABLED'));
        if ($track_all_enabled != NULL && strtoupper($track_all_enabled) == "TRUE") {
            return true;
        }
        return false;
    }

    /**
     * Add custom transaction name for current transaction.
     * @param $transactionName
     */
    public static function setTransactionName($transactionName)
    {
        self::$transactionName = $transactionName;
    }

    /**
     * Add more ignore functions to profiling options.
     *
     * @param array<string> $functionNames
     * @return void
     */
    public static function addIgnoreFunctions(array $functionNames)
    {
        foreach ($functionNames as $functionName) {
            self::$defaultOptions['ignored_functions'][] = $functionName;
        }
    }

    public static function shutdown()
    {
        if (self::$mode === self::MODE_DISABLED) {
            return;
        }

        $lastError = error_get_last();

        if ($lastError && ($lastError["type"] === E_ERROR || $lastError["type"] === E_PARSE || $lastError["type"] === E_COMPILE_ERROR)) {
            $lastError['trace'] = function_exists('stackify_fatal_backtrace') ? stackify_fatal_backtrace() : null;
            array_push(self::$exceptions, $lastError);
        }

        self::stop();

    }


    /**
     * Stop all profiling actions and submit collected data.
     */
    public static function stop()
    {
        if (self::$mode === self::MODE_DISABLED) {
            return;
        }

        $mode = self::$mode;

        // stop profiler
        if (($mode & self::MODE_FULL) > 0 || self::$error) {
            stackify_disable();
        }
        self::$mode = self::MODE_DISABLED;

        if (!self::$hasExecutedTransactionFunction) {
            self::sendTrace();
        }
     }

    /**
     * Adds AWS Lambda properties to traces if available
     */
     public static function applyAWSLambdaProperties() {
        if (isset($_SERVER['AWS_LAMBDA_FUNCTION_NAME'])) {
            self::$trace['call'] = $_SERVER['AWS_LAMBDA_FUNCTION_NAME'] . "::" . $_SERVER['_HANDLER'];
            self::$trace['props']['REPORTING_URL'] = $_SERVER['AWS_LAMBDA_FUNCTION_NAME'];
            self::$trace['props']['APPLICATION_FILESYSTEM_PATH'] = "/";
        }
     }

    /**
     * Converts frames to trace then writes to transport
     */
    public static function sendTrace(){
        // get frames
        $frames = self::$stackifyExtension->getTraceFrames();
        // link frames and convert to trace
        self::$trace = self::linkFrames($frames);
        // apply aws lambda properties if available
        self::applyAWSLambdaProperties();

        $exceptions_count = sizeof(self::$exceptions);
        if (sizeof(self::$exceptions) > 0) {
            self::$trace['exceptions'] = array();
            for ($i = 0; $i < $exceptions_count;$i++) {

                $trace_exception = array();
                $exception_message_parts = explode("\n", self::$exceptions[$i]['message']);

                if (sizeof($exception_message_parts) >= 1) {

                    $trace_exception['Timestamp'] = strval((int) self::$trace['reqEnd']);
                    $trace_exception['Exception'] = $exception_message_parts[0];
                    $trace_exception['Message'] = $exception_message_parts[0];

                    if (sizeof($exception_message_parts) >= 3) {
                        $trace_exception['CaughtBy'] = $exception_message_parts[2];
                    } else {
                        $trace_exception['CaughtBy'] = "Unknown";
                    }

                    $trace_exception['Frames'] = array();
                    foreach ($exception_message_parts as $exception_message_part_key => $exception_message_part) {
                        $exceptionFrame = array();
                        $exceptionFrame['Method'] = $exception_message_part;
                        array_push($trace_exception['Frames'], $exceptionFrame);
                    }

                    array_push(self::$trace['exceptions'], $trace_exception);
                }
            }
        }

       $output_json = self::safe_json_encode(self::$trace, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_NUMERIC_CHECK);

       if ($output_json === false ) {
            try {
                $serializedString = serialize(self::$trace);
                $errorMaxLength = ini_get("log_errors_max_len");

                if ($errorMaxLength !== false && strlen($serializedString) < $errorMaxLength) {
                    self::log(3, "Stackify\Profiler::sendTrace - json_encode('trace') - Payload: ".$errorMaxLength);
                } else {
                    self::log(3, "Stackify\Profiler::sendTrace - json_encode('trace') - Payload Error: Greater than the error text limit (log_errors_max_len)");
                }
            } catch (\Exception $e) {
                self::log(3, "Stackify\Profiler::sendTrace - json_encode('trace') - serialize('trace') -> Exception: ". $e->getMessage());
            }

        } else {

            if (self::$transport == null || self::$transport == "log") {
                try {
                    // write to trace log
                    $prefix = gmdate("Y-m-d, H:i:s.u") . "> ";
                    $output_final = $prefix . $output_json . "\n";
                    self::writeToTraceLog($output_final);
                } catch (\Exception $e) {
                    self::log(3, "Stackify\Profiler::sendTrace - error writing trace to log file.". $e->getMessage());
                }
            } else if (self::$transport == "console") {
                try {
                    // write to console
                    $output_json_gzip = gzencode($output_json, 6);
                    $output_json_gzip_base64 = base64_encode($output_json_gzip);
                    $prefix = "STACKIFY-TRACE: ";
                    $output_final = $prefix . $output_json_gzip_base64 . "\n";
                    echo($output_final);
                } catch (\Exception $e) {
                    self::log(3, "Stackify\Profiler::sendTrace - error writing trace console.". $e->getMessage());
                }
            } else if (self::$transport == "agent_http") {
                try {
                    error_log("sending message 1");
                    $output_json = "[" . $output_json . "]";
                    $url = self::$transportHttpEndpoint . "/traces";
                    error_log("sending message 2");
                    //open connection
                    $ch = curl_init();
                    error_log("sending message 3");
                    //set the url, number of POST vars, POST data
                    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
                    curl_setopt($ch,CURLOPT_URL, $url);
                    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
                    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $output_json);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                    curl_setopt($ch, CURLOPT_HTTPHEADER, array(
                            'Content-Type: application/json',
                            'Content-Length: ' . strlen($output_json))
                    );
                    error_log("sending message 4");

                    //execute post
                    $result = curl_exec($ch);
                    error_log("sending message 5");
                    //close connection
                    curl_close($ch);
                    error_log("sending message 6");



                } catch (\Exception $e) {
                    self::log(3, "Stackify\Profiler::sendTrace - error posting trace to [" . self::$transportHttpEndpoint . "].". $e->getMessage());
                } 
            }
        }

        self::$traceMapByParentFrameId = null;
        self::$customUrlTransactionName = null;
        self::$trace = null; // free memory
    }

    /**
     * Fixes json_encode posiblle problems
     * http://php.net/manual/en/function.json-last-error.php#121233
     * https://stackoverflow.com/questions/10199017/how-to-solve-json-error-utf8-error-in-php-json-decode
     */
    public static function safe_json_encode($value, $options = 0, $depth = 512, $utfErrorFlag = false) {
        if ((defined('PHP_MAJOR_VERSION') && PHP_MAJOR_VERSION >= 5) && (defined('PHP_MINOR_VERSION') && PHP_MINOR_VERSION >= 6) ) {
            $encoded = json_encode($value, $options, $depth);
        } else {
            $encoded = json_encode($value, $options);
        }

        switch (json_last_error()) {
            case JSON_ERROR_NONE:
                return $encoded;
            case JSON_ERROR_DEPTH:
                self::log(3, "Stackify\Profiler::stop - json_encode('trace') - Maximum stack depth exceeded!");
                self::log(3, "Stackify\Profiler::stop - json_encode('trace') - ErrorMessage: ".json_last_error_msg());
                return false;
            case JSON_ERROR_STATE_MISMATCH:
                self::log(3, "Stackify\Profiler::stop - json_encode('trace') - Underflow or the modes mismatch!");
                self::log(3, "Stackify\Profiler::stop - json_encode('trace') - ErrorMessage: ".json_last_error_msg());
                return false;
            case JSON_ERROR_CTRL_CHAR:
                self::log(3, "Stackify\Profiler::stop - json_encode('trace') - Unexpected control character found!");
                self::log(3, "Stackify\Profiler::stop - json_encode('trace') - ErrorMessage: ".json_last_error_msg());
                return false;
            case JSON_ERROR_SYNTAX:
                self::log(3, "Stackify\Profiler::stop - json_encode('trace') - Syntax error, malformed JSON!");
                self::log(3, "Stackify\Profiler::stop - json_encode('trace') - ErrorMessage: ".json_last_error_msg());
                return false;
            case JSON_ERROR_UTF8:
                $clean = self::utf8ize($value);
                if ($utfErrorFlag) {
                    self::log(3, "Stackify\Profiler::stop - json_encode('trace') - UTF8 encoding error!");
                    self::log(3, "Stackify\Profiler::stop - json_encode('trace') - ErrorMessage: ".json_last_error_msg());
                    return false;
                }
                return self::safe_json_encode($clean, $options, $depth, true);
            default:
                self::log(3, "Stackify\Profiler::stop - json_encode('trace') - Unknown error!");
                return false;
        }

    }

    /**
     * Fixes json_encode JSON_ERROR_UTF8 error
     * http://php.net/manual/en/function.json-last-error.php#115980
     */
    public static function utf8ize($mixed) {
        if (is_array($mixed)) {
            foreach ($mixed as $key => $value) {
                $mixed[$key] = self::utf8ize($value);
            }
        } else if (is_string ($mixed)) {
            return utf8_encode($mixed);
        }
        return $mixed;
    }

    /**
     * Handles any post-processing on frames
     */
    public static function post_process_frames($frames)
    {
        $processed_frames = array();

        foreach ($frames as $frame)  {

            if (isset($frame['props']['PREFIX_RESPONSE_BODY'])) {
                $response_headers = array();
                $response_body = $frame['props']['PREFIX_RESPONSE_BODY'];
                $response_body_parts = explode ( "\r\n", $response_body);

                foreach ($response_body_parts as $response_body_part) {
                    if (empty($response_body_part)) {
                        break;
                    } else {
                        $del_position = strpos($response_body_part, ":");
                        if($del_position !== false) {

                            $key = substr($response_body_part, 0, $del_position);
                            $value = substr($response_body_part, $del_position + 1, strlen($response_body_part));

                            if (!empty($key) && !empty($value)) {
                                $response_header = array();
                                $response_header[trim($key)] = trim($value);
                                array_push($response_headers, $response_header);
                            }
                        }
                    }
                }

                $frame['props']['PREFIX_RESPONSE_HEADERS'] = self::safe_json_encode($response_headers);
            }

            array_push($processed_frames, $frame);
        }

        return $processed_frames;
    }

    /**
     * Removes slow frames
     */
    public static function trim_frames(&$frames)
    {
      // [frame_id] -> [frame]  map
      $frame_id_map = array();
      foreach ($frames as $frame_key => $frame) {
        $frame_id_map[$frame['props']['FRAME_ID']] = $frame;
      }

      // [frame_id] -> [parent_frame_id] map
      $frame_id_to_parent_frame_id = array();
      foreach ($frames as $frame_key => $frame) {
        if (isset($frame['props']['PARENT_FRAME_ID'])) {
          $parent_frame_id = $frame['props']['PARENT_FRAME_ID'];
          $parent_frame = $frame_id_map[$parent_frame_id];
          $parent_parent_frame_id = 0;
          if (isset($parent_frame['props']['PARENT_FRAME_ID'])) {
            $parent_parent_frame_id = $parent_frame['props']['PARENT_FRAME_ID'];
          }
          $frame_id_to_parent_frame_id[$frame['props']['FRAME_ID']] = $parent_parent_frame_id;
        }
      }

      // remove frames if timings are missing
      foreach ($frames as $frame_key => $frame) {
        if (!array_key_exists('reqBegin', $frame) || !array_key_exists('reqBegin', $frame)) {
          unset($frames[$frame_key]);
        }
      }

      // remove fast frames
      foreach ($frames as $frame_key => $frame) {
        $frame_id = intval($frame['props']['FRAME_ID']);
        if ($frame_id > 0) {  // skip root frame
          $req_start_ms = doubleval($frame['reqBegin']);
          // edge case where reqEnd is not set - avoid error by setting to reqBegin (likely will be removed as a fast frame)
          $req_end_ms = array_key_exists('reqEnd', $frame) ? doubleval($frame['reqEnd']) : 0;
          $elapsed_ms = $req_end_ms - $req_start_ms;
          $property_count = sizeof($frame['props']);
          if ($elapsed_ms < 1 && $property_count < 4) {
            unset($frames[$frame_key]);
          }
        }
      }

      // trimmed [frame_id] -> [frame]  map
      $trimmed_trace_map = array();
      foreach ($frames as $frame_key => $frame) {
        $trimmed_trace_map[$frame['props']['FRAME_ID']] = $frame;
      }

      // update [parent_frame_id] on needed frames
      foreach ($frames as $frame_key => $frame) {
        if (isset($frame['props']['PARENT_FRAME_ID'])) {
          $parent_frame_id = $frame['props']['PARENT_FRAME_ID'];
          if (isset($parent_frame_id)) {
            $count = 0;
            while (!isset($trimmed_trace_map[$parent_frame_id]) && $count < 25) {
              $count = $count + 1; // limit look loop
              $parent_frame_id = $frame_id_to_parent_frame_id[$parent_frame_id];
            }
            if (!isset($parent_frame_id)) {
              $parent_frame_id = 0;
            }
            $frame['props']['PARENT_FRAME_ID'] = $parent_frame_id;
          }
        }
      }
    }

    /**
     * Converts array of frames into a trace tree.
     * @param $frames
     * @return trace
     */
    public static function linkFrames($frames)
    {
        $show_fast_functions = false;
        if (isset(self::$defaultOptions['show_fast_functions']) && self::$defaultOptions['show_fast_functions'] == 1) {
            $show_fast_functions = true;
        }

        $trace = $frames[0];

        if (!$show_fast_functions) {
          self::trim_frames($frames);
        }

        $frames = self::post_process_frames($frames);

        self::setupFrameStack($trace, $frames);

        self::setupTraceProperties($trace);
        return $trace;
    }

    /**
     * Add trace level properties.
     */
    static function setupTraceProperties(&$trace)
    {
        $trace['props']['APPLICATION_PATH'] = "/";
        $trace['props']['APPLICATION_FILESYSTEM_PATH'] = $_SERVER["DOCUMENT_ROOT"];
        $trace['props']['APPLICATION_NAME'] = self::$applicationName;
        $trace['props']['APPLICATION_ENV'] = self::$environmentName;
        $trace['props']['CATEGORY'] = 'PHP';
        $trace['props']['THREADID'] = 0;

        if (self::$isCli) {
            $trace['call'] = 'CLI';
        }

        if (!self::$isCli) {
            $trace['props']['URL'] = self::full_url($_SERVER);
        }

        // allow transactionName to take precedence for reporting_url
        if (empty(self::$transactionName)) {
            $reporting_url = stackify_transaction_name();
        } else {
            $reporting_url = self::$transactionName;
        }

        // Custom URL from stackify.json setting
        if (empty($reporting_url)) {
            $customized_url = self::custom_url();
            $reporting_url = ($customized_url != null) ? $customized_url : $reporting_url;
        }

        if (empty($reporting_url)) {
            if (self::$isCli) {
                $reporting_url = basename($_SERVER['PHP_SELF'], '.php');
            } else {
                $reporting_url =  $_SERVER['REQUEST_URI'];
                $reporting_url = array_filter(explode('?', $reporting_url))[0];
                $reporting_url = rtrim($reporting_url, '/');
                if (empty($reporting_url)) {
                    $reporting_url = '/'; // default
                }
            }
        }

        $trace['props']['REPORTING_URL'] = $reporting_url;

        $rum_enabled = strval(ini_get("stackify.rum_enabled"));
        if ($rum_enabled != NULL && $rum_enabled == "1") {
            $trace['props']['RUM'] = "TRUE";
        }

        $prefix_enabled = strval(ini_get("stackify.prefix_enabled"));
        if ($prefix_enabled != NULL && $prefix_enabled == "1") {
            $trace['props']['PREFIX'] = "TRUE";

            // add request headers
            $request_headers = array();
            foreach (getallheaders() as $name => $value) {
                $request_header = [
                    $name => $value
                ];
                array_push($request_headers, $request_header);
            }
            $trace['props']['PREFIX_REQUEST_HEADERS'] =  self::safe_json_encode($request_headers, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_NUMERIC_CHECK);

            // add request body
            $request_body = file_get_contents('php://input');
            $trace['props']['PREFIX_REQUEST_BODY'] = $request_body;
            $trace['props']['PREFIX_REQUEST_SIZE_BYTES'] = strlen($request_body);

            // add response headers
            $response_headers = array();
            foreach (headers_list() as $header) {
                $header_parts = explode (':', $header);
                if (count($header_parts) == 2) {
                    $name = $header_parts[0];
                    $value = $header_parts[1];
                    $response_header = [
                        $name => $value
                    ];
                    array_push($response_headers, $response_header);
                }
            }
            $trace['props']['PREFIX_RESPONSE_HEADERS'] = self::safe_json_encode($response_headers, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_NUMERIC_CHECK);
        }

        if (!self::$isCli) {
            $trace['props']['METHOD'] = $_SERVER['REQUEST_METHOD'];
            $trace['props']['STATUS'] = http_response_code();
        }

        $trace['props']['TRACETYPE'] = self::$isCli ? 'TASK' : 'WEBAPP';
        $trace['props']['TRACE_SOURCE'] = 'PHP';
        $trace['props']['TRACE_TARGET'] = 'RETRACE';
        $trace['props']['HOST_NAME'] = gethostname();

        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            $trace['props']['OS_TYPE'] = 'WINDOWS';
        } else {
            $trace['props']['OS_TYPE'] = 'LINUX';
        }

        // handle if getmypid is disabled - default to 0
        $pid = getmypid();
        $pid = isset($pid) ? $pid : '0';

        $trace['props']['PROCESS_ID'] = $pid;
        $trace['props']['TRACE_VERSION'] = "2.0";

    }

    /**
     * Returns customized reporting url based from stackify.json settings.
     * @param $reporting_url
     */
    public static function custom_url()
    {
        if (self::$customUrlTransactionName != null) {
            return self::$customUrlTransactionName;
        }
    }
    /**
     * Returns the 1st element of the path passed in (will use back or forward slash).
     */
    static function get_first_path_element($path)
    {
        if (strpos($path, '/') !== false) {
            $application_path_elements = explode('/', $path);
            $application_path_elements = array_filter($application_path_elements);
            return array_values($application_path_elements)[0];
        } else if (strpos($path, '\\') !== false) {
            $application_path_elements = explode('\\', $path);
            $application_path_elements = array_filter($application_path_elements);
            return array_values($application_path_elements)[0];
        }

        return $path;
    }

    /**
     * Returns full url for current application request.
     */
    static function full_url($s, $use_forwarded_host = false)
    {
        return self::remove_trailing_slash(self::url_origin($s, $use_forwarded_host) . $s['REQUEST_URI']);
    }

    /**
     * Utility to remove trailing forward or backslash from value passed in.
     */
    static function remove_trailing_slash($v)
    {
        if (substr($v, -1) == '/') {
            $v = substr($v, 0, -1);
        } else if (substr($v, -1) == '\\') {
            $v = substr($v, 0, -1);
        }
        return $v;
    }

    /**
     * Returns origin portion of current application request.
     */
    static function url_origin($s, $use_forwarded_host = false)
    {
        $ssl = (!empty($s['HTTPS']) && $s['HTTPS'] == 'on');
        $sp = strtolower($s['SERVER_PROTOCOL']);
        $protocol = substr($sp, 0, strpos($sp, '/')) . (($ssl) ? 's' : '');
        $port = $s['SERVER_PORT'];
        $port = ((!$ssl && $port == '80') || ($ssl && $port == '443')) ? '' : ':' . $port;
        $host = ($use_forwarded_host && isset($s['HTTP_X_FORWARDED_HOST'])) ? $s['HTTP_X_FORWARDED_HOST'] : (isset($s['HTTP_HOST']) ? $s['HTTP_HOST'] : null);
        $host = isset($host) ? $host : (isset($s['HTTP_HOST']) ? $s['HTTP_HOST'] . $port : '');
        $url_origin = $protocol . '://' . $host;
        return $url_origin;
    }

    /**
     * Adds child frames to $current_frame (searches $frames).
     * Function is recursive.
     * @return void
     */
    public static function setupFrameStack(&$current_frame, $frames)
    {
        // setup map w/ parent frame id as keys
        if (!isset(self::$traceMapByParentFrameId)) {
            self::$traceMapByParentFrameId = array();

            foreach ($frames as $frame_key => $frame) {


                if (array_key_exists($frame['call'], self::$defaultOptions['watches'])) {
                    $watchObject = self::$defaultOptions['watches'][$frame['call']];

                    // Add TRACKED_FUNC property
                    if (isset($watchObject['trackedFunction']) && $watchObject['trackedFunction'] == 'true') {
                        $frame['props']['TRACKED_FUNC'] = self::$defaultOptions['watches'][$frame['call']]['trackedFunctionName'];
                    }

                    // Set $customUrlTransactionName for Custom Reporting URL.
                    // Check if executed transaction's callback - get the custom transaction name for CUSTOM URL of the root frame specially if having nested  transaction functions call
                    if (self::$hasExecutedTransactionFunction) {
                        if (isset($watchObject['transactionName']) && $watchObject['transactionName'] != "" && $frame['props']['FRAME_ID'] == 1) {
                            self::$customUrlTransactionName = $watchObject['transactionName'];
                        }

                    } else {    // normal setting
                        if (isset($watchObject['transactionName']) && self::$customUrlTransactionName == null) {
                            self::$customUrlTransactionName = self::$defaultOptions['watches'][$frame['call']]['transactionName'];
                        }
                    }
                }

                if (isset($frame['props']['PARENT_FRAME_ID'])) {
                    if (!array_key_exists($frame['props']['PARENT_FRAME_ID'], self::$traceMapByParentFrameId)) {
                        self::$traceMapByParentFrameId[$frame['props']['PARENT_FRAME_ID']] = array();
                    }
                    array_push(self::$traceMapByParentFrameId[$frame['props']['PARENT_FRAME_ID']], $frame);
                }
            }
        }

        $current_frame['stacks'] = array();
        if (array_key_exists($current_frame['props']['FRAME_ID'], self::$traceMapByParentFrameId)) {
            $child_frames = self::$traceMapByParentFrameId[$current_frame['props']['FRAME_ID']];

            foreach ($child_frames as $child_frame_key => $child_frame) {
                self::setupFrameStack($child_frame, $frames);
                $current_frame['stacks'][] = $child_frame;
            }
        }
    }

    /**
     * Checks if file exceeds max size.
     * @param $filename
     * @return bool
     */
    public static function isFileOverSizeLimit($filename)
    {
        $max_file_size_bytes = 50 * 1024 * 1024;
        clearstatcache();
        return filesize($filename) > $max_file_size_bytes;
    }

    /**
     * Creates a new trace log file if current file is over limit.
     * Will also delete out older file in the process.
     * @param $filename_current_link_source - actual file path for current log file
     * @param $filename_current - symlink to current log file
     * @param $max_files - max amount of trace log files to keep
     */
    protected static function rollOverTraceLog($filename_current_link_source, $filename_current,  $max_files)
    {
        set_error_handler("Stackify\Profiler::stackifyErrorHandler");

        if (self::isFileOverSizeLimit($filename_current)) {

            Util\Sync::$lock = self::$logFilePath . DIRECTORY_SEPARATOR . '.lock';
            Util\Sync::call(function () use ($filename_current_link_source, $filename_current, $max_files) {
                // double check if file is over size
                if (self::isFileOverSizeLimit($filename_current_link_source)) {
                    // find the current # log file we are writing to. (name-#.log)
                    $index_start = strrpos($filename_current_link_source, "-");
                    $current_log_index = substr($filename_current_link_source, $index_start + 1, -4);

                    // delete oldest file
                    $max_file_index = $current_log_index - $max_files + 1;
                    if ($max_file_index > 0) {
                        $delete_filename = substr($filename_current_link_source, 0, $index_start) . "-" . $max_file_index . ".log";

                        if (file_exists($delete_filename)) {
                            if (unlink($delete_filename) === false) {
                                self::log(1, "Profiler::rollOverTraceLog - Util\Sync::call - Unable to unlink delete_filename: ".$delete_filename);
                            }
                        }
                    }

                    // increment # to write to
                    $next_log_index = $current_log_index + 1;
                    $new_filename = substr($filename_current_link_source, 0, $index_start) . "-" . $next_log_index . ".log";

                    if (file_exists($new_filename)) {
                        if (unlink($new_filename) === false) {
                            self::log(1, "Profiler::rollOverTraceLog - Util\Sync::call - Unable to unlink new_filename: ".$new_filename);
                        }
                    }

                    if (is_link($filename_current)) {
                        if (unlink($filename_current) === false) {
                            self::log(1, "Profiler::rollOverTraceLog - Util\Sync::call - Unable to unlink filename_current: ".$filename_current);
                        }
                    }

                    if (touch($new_filename) === false) {
                        self::log(1, "Profiler::rollOverTraceLog - Util\Sync::call - Unable to touch new_filename: ".$new_filename);
                    }

                    if (chmod($new_filename, 0777) === false) {
                        self::log(1, "Profiler::rollOverTraceLog - Util\Sync::call - Unable to change mod new_filename: ".$new_filename);
                    }

                    if (symlink($new_filename, $filename_current) === false) {
                        self::log(1, "Profiler::rollOverTraceLog - Util\Sync::call - Unable to link new_filename: ".$new_filename." to filename_current: ".$filename_current);
                    }

                    clearstatcache();
                }

            });
        }
        restore_error_handler();
    }

    /**
     * Removes any broken symlink log files
     */
    protected static function cleanupFiles($logFilePath)
    {
        set_error_handler("Stackify\Profiler::stackifyErrorHandler");

        Util\Sync::$lock = $logFilePath . DIRECTORY_SEPARATOR . '.lock';
        Util\Sync::call(function () use ($logFilePath) {
            foreach (scandir($logFilePath . DIRECTORY_SEPARATOR) as $entry) {
                $path = $logFilePath . DIRECTORY_SEPARATOR . $entry;
                if (is_link($path) && file_exists($path) === false) {
                    if (unlink($path) === false) {
                        self::log(1, "Profiler::cleanupFiles - Util\Sync::call - Unable to unlink path: ".$path);
                    }
                }
            }
        });

        restore_error_handler();
    }

    /**
     * Writes contents to trace log file.
     * @param $content
     */
    protected static function writeToTraceLog($content)
    {
        if (self::isRequiredDirOk()) {
            set_error_handler("Stackify\Profiler::stackifyErrorHandler");

            $logFilePath = self::$logFilePath;
            $threadId = "#0";
            $file_date_hash = md5(gmdate("YmdH"));
            $filename_base = gethostname() . "-" . $file_date_hash . $threadId;
            $filename_current = $logFilePath . DIRECTORY_SEPARATOR . $filename_base . ".log"; // symlink log file (for current file)

            // create a log file if one does not exist
            if (!file_exists($filename_current)) {

                Util\Sync::$lock = $logFilePath . DIRECTORY_SEPARATOR . '.lock';
                Util\Sync::call(function () use ($filename_current, $filename_base, $logFilePath) {
                    // double check
                    // ensure it still doesn't exist
                    if (file_exists($filename_current) === false) {
                        // delete all files w/ current hostname
                        $glob_result = glob($logFilePath . DIRECTORY_SEPARATOR . $filename_base . "*");
                        foreach ($glob_result as $f) {
                            if (file_exists($f) === false) {
                                if (unlink($f) === false) {
                                    self::log(1, "Profiler::writeToTraceLog - Util\Sync::call - Unable to unlink file: " . $f);
                                }
                            }
                        }

                        if ($glob_result === false) {
                            self::log(1, "Profiler::writeToTraceLog - Util\Sync::call - Glob failed: " . $logFilePath . DIRECTORY_SEPARATOR . $filename_base . "*");
                        }

                        // create 1st file and symlink
                        if (touch($logFilePath . DIRECTORY_SEPARATOR . $filename_base . "-1.log") === false) {
                            self::log(1, "Profiler::writeToTraceLog - Util\Sync::call - Unable to touch file: " . $filename_base . "-1.log");
                        }

                        if (chmod($logFilePath . DIRECTORY_SEPARATOR . $filename_base . "-1.log", 0777) === false) {
                            self::log(1, "Profiler::writeToTraceLog - Util\Sync::call - Unable to change mod file: " . $filename_base . "-1.log");
                        }

                        if (symlink($logFilePath . DIRECTORY_SEPARATOR . $filename_base . "-1.log", $filename_current) === false) {
                            self::log(1, "Profiler::writeToTraceLog - Util\Sync::call - Unable to link file: " . $filename_base . "-1.log to file: " . $filename_current);
                        }
                        clearstatcache();
                    }
                });

            }

            $filename_current_link_source = readlink($filename_current);
            if ($filename_current_link_source === false) {
                self::log(1, "Profiler::writeToTraceLog - Unable to read symbolic link filename_current_link_source: " . $filename_current);
            }

            $file_put_contents = file_put_contents($filename_current_link_source, $content, FILE_APPEND | LOCK_EX);
            if ($file_put_contents === false) {
                self::log(1, "Profiler::writeToTraceLog - Unable to write contents to filename_current_link_source: " . $filename_current_link_source . " symlink: " . $filename_current);
            }

            // see if we have reached size limit
            // Only run this check every 25 requests
            if (rand(1, 25) == 25) {
                self::rollOverTraceLog($filename_current_link_source, $filename_current, self::$max_files);
            }

            if (rand(1, 100) == 100) {
                self::cleanupFiles(self::$logFilePath);
            }

            restore_error_handler();
        }
    }

    public static function setupLogDirectories() {
        $prefix_enabled = strval(ini_get("stackify.prefix_enabled"));
        if ($prefix_enabled != NULL && $prefix_enabled == "1") {
            self::$logFilePath =  "/usr/local/prefix/log";
            self::$errorLog = "/usr/local/prefix/debug/stackify-php-apm.log";
        } else {
            self::$logFilePath =  "/usr/local/stackify/stackify-php-apm/log";
            self::$errorLog = "/usr/local/stackify/stackify-php-apm/log/stackify-php-apm.log";
        }
    }

    /**
     * auto start profiler for web and cli scenarios
     */
    public static function autoStart()
    {
        self::setupLogDirectories();

        if (self::isStarted() === false) {
            switch (php_sapi_name()) {
                case 'cli':
                    if (ini_get("stackify.monitor_cli")) {
                        self::$isCli = true;
                        self::start(array('service' => 'cli'));
                    }
                    break;
                default:
                    self::start();
            }
        }

        if (self::requiresDelegateToOriginalPrependFile()) {
            require_once ini_get("auto_prepend_file");
        }
    }

    public static function isStarted()
    {
        return self::$mode !== self::MODE_DISABLED;
    }

    /**
     * Start profiling request.
     *
     * @param array $options
     */
    public static function start($options = array())
    {
        stackify_disable(); // this discards any data that was collected up to now and restarts.
        $defaults = array(
            'collect' => self::MODE_FULL,
            'transport' => isset($_SERVER['STACKIFY_TRANSPORT']) ? $_SERVER['STACKIFY_TRANSPORT'] : ini_get("stackify.transport"),
            'transport_http_endpoint' => isset($_SERVER['STACKIFY_TRANSPORT_HTTP_ENDPOINT']) ? $_SERVER['STACKIFY_TRANSPORT_HTTP_ENDPOINT'] : ini_get("stackify.transport_http_endpoint"),
            'application_name' => isset($_SERVER['STACKIFY_APPLICATION_NAME']) ? $_SERVER['STACKIFY_APPLICATION_NAME'] : ini_get("stackify.application_name"),
            'environment_name' => isset($_SERVER['STACKIFY_ENVIRONMENT_NAME']) ? $_SERVER['STACKIFY_ENVIRONMENT_NAME'] : ini_get("stackify.environment_name"),
            'service' => isset($_SERVER['STACKIFY_SERVICE']) ? $_SERVER['STACKIFY_SERVICE'] : ini_get("stackify.service"),
            'framework' => isset($_SERVER['STACKIFY_FRAMEWORK']) ? $_SERVER['STACKIFY_FRAMEWORK'] : ini_get("stackify.framework"),
        );
        $options = array_merge($defaults, $options);

        self::init($options);
        self::enableProfiler();
    }

    /**
     * Check required directories/folders/file permissions and availability, if something wrong don't proceed.
     *
     * @return boolean
     */
    private static function isRequiredDirOk()
    {
        // Check if log folder is present and writable
        if (self::$logFilePathWritable === null) {
            self::$logFilePathWritable = is_writable(self::$logFilePath);
            if (!self::$logFilePathWritable) {
                self::log(1, "Couldn't start PHP profiler: ". self::$logFilePath ." is not writable.");
            }
        }
        return self::$logFilePathWritable;
    }

    /**
     * Initialize profiler.
     *
     * @param $options
     */
    private static function init($options)
    {
        if (self::$shutdownRegistered == false) {
            register_shutdown_function(array("Stackify\\Profiler", "shutdown"));
            self::$shutdownRegistered = true;
        }

        if ($options['framework']) {
            self::setupFramework($options['framework']);
        }

        self::$applicationName = $options['application_name'];
        self::$environmentName = $options['environment_name'];
        self::$transport = $options['transport'];
        self::$transportHttpEndpoint = $options['transport_http_endpoint'];
        self::$mode = self::MODE_FULL;
        self::$error = false;
    }

    /**
     * Adjusts profiler configuration based on passed in framework.
     * @param $framework
     */
    public static function setupFramework($framework)
    {
        self::$defaultOptions['framework'] = $framework;
    }

    /**
     * Enable the profiler.
     *
     * @return void
     */
    private static function enableProfiler()
    {
        self::$mode = self::MODE_FULL;
        self::$stackifyExtension = new \Stackify\Profiler\StackifyExtension();

        $setting = self::readCustomConfigFile('stackify.json','instrumentation');

        // default to empty array
        if (!is_array($setting)) {
            $setting = array();
        }

        // if aws lambda is detected
        if (isset($_SERVER['AWS_LAMBDA_FUNCTION_NAME'])) {
            // track fast functions
            self::$defaultOptions['show_fast_functions'] = 1;
            // add handler function to custom instrumentation
            $lambda_call = array("class" => "", "method" => $_SERVER['_HANDLER'], "startTrace" => true);
            array_push($setting, $lambda_call);
        }

        self::map_stackify_json($setting);

        // Setting up transaction callback
        if( self::$isCli && !empty(self::$defaultOptions['transaction_functions']) ) {
            self::$defaultOptions = array_merge(self::$defaultOptions, array(
                'transaction_callback' => function() {
                    self::$hasExecutedTransactionFunction = true;

                    // Start linking frames here if there is atleast 1 function call sets as TRANSACTION FUNCTION
                    self::sendTrace();
                }
            ));
        }

        // check if track all is enabled
        if (self::isTrackAll()) {
            self::$defaultOptions['ignored_functions'] = [];
            self::$defaultOptions['show_fast_functions'] = 1;
        }

        stackify_enable(0, self::$defaultOptions);

        foreach (self::$defaultOptions['watches'] as $key => $val) {
            self::$stackifyExtension->watchSpan($key, $val['category']);
        }
    }

    /**
     * Read custom JSON file then push to self::$defaultOptions['watches']
     * @param $filename
     * @param $propertyToRead
     * @return array
     */
    public static function readCustomConfigFile($filename, $propertyToRead)
    {
        $configFileLocations = array(
            ini_get('stackify.config_file'),
            $_SERVER['DOCUMENT_ROOT'].'/'.$filename,
            '/usr/local/stackify/stackify-php-apm/'.$filename,
            '/usr/local/prefix/'.$filename
        );

        foreach($configFileLocations as $fileDir)
        {
            if(self::is_file_not_empty($fileDir)) {
                try {
                   $content = file_get_contents($fileDir);
                }
                catch (\Exception $ignored) {
                }

                $json = json_decode($content, TRUE);

                if($json !== "" )
                {
                    foreach ($json as $key => $val)
                    {
                        if ($key == $propertyToRead) {
                            return $val;
                        }
                    }
                }
                break;
            }
        }
    }

    /** Checks if file exists, it's a file, file is readable, and file is not empty
     * @param $file
     * @return boolean
     */
    private static function is_file_not_empty($file)
    {
        if($file !== "" && file_exists($file) && is_file($file) && is_readable($file) && filesize($file) > 0)
        {
            return true;
        } else
            return false;
    }

    /**
     * Returns the mapped items from stackify.json. Expose for the user to review
     * @return array
     */
    public static function get_watches()
    {
        return self::$defaultOptions['watches'];
    }

    /**
     * Iterates array from stackify.json then map all items
     * @param $setting
     */
    public static function map_stackify_json($setting)
    {
        if (is_array($setting) || is_object($setting))
        {
            foreach ($setting as $setting_key => $setting_props)
            {
                if ( isset($setting_props['method']) && $setting_props['method'] != "" )
                {
                    $category = "";  // Value might be 'View' | 'Event' but for now set this to empty
                    $sro = ($setting_props['class'] !== "") ? '::' : '';
                    $call = $setting_props['class'].$sro.$setting_props['method'];

                    $watches['call'] = $call;
                    $watches['category']  = $category;

                    // Checks if trackedFunction is set. Used for TRACKED FUNCTIONS
                    if ( isset($setting_props['trackedFunction']) && $setting_props['trackedFunction'] != "" && is_bool($setting_props['trackedFunction'])) {   // if so, set the item
                        $watches['trackedFunction']  = ($setting_props['trackedFunction']) ? 'true' : 'false';
                        $str = (isset($setting_props['trackedFunctionName']) && $setting_props['trackedFunction'] == true && $setting_props['trackedFunction'] != "") ? $setting_props['trackedFunctionName']: "";
                        $watches['trackedFunctionName'] = self::create_template($call, $setting_props, $str);
                    } else {    // else don't set
                        unset($watches['trackedFunction']);
                        unset($watches['trackedFunctionName']);
                    }

                    // Checks if transactionName is set. Used for CUSTOM URL
                    if ( isset($setting_props['transactionName']) ) {
                        $str = (isset($setting_props['transactionName'])) ? $setting_props['transactionName'] : "";
                        $watches['transactionName']  = self::create_template($call, $setting_props, $str);
                    } else {
                        unset($watches['transactionName']);
                    }

                    // Checks if CLI, if so, set startTrace.
                    if ( self::$isCli && isset($setting_props['startTrace']) && is_bool($setting_props['startTrace']) ) {

                        $watches['startTrace']  = ($setting_props['startTrace']) ? 'true' : 'false';

                        // Map function call as transaction function. Avoid duplicate
                        if ( !in_array( $call, self::$defaultOptions['transaction_functions']) && $setting_props['startTrace'] ) {
                            array_push(self::$defaultOptions['transaction_functions'], $call);
                        }

                    } else {
                        unset($watches['startTrace']);
                    }

                    // Checks for duplicate function call.
                    if ( isset(self::$defaultOptions['watches'][$call]) ) {
                        $config_file = ini_get('stackify.config_file');
                        self::log(1, "You may have more than one setting of $call in $config_file, only one has been mapped. Use \Stackify\Profiler::get_watches() to review the successfully mapped custom instrumentation config.");
                    } else {
                        self::$defaultOptions['watches'][$call] = $watches;
                    }
                }
            }
        }
    }

    /**
     * Creates template by replacing {{ClassName}} and {{MethodName}} with class and method values.
     * @param string $call
     * @param array $arr
     * @param string $string
     * @return string
     */
    public static function create_template($call, $arr, $string)
    {
        if ($string != "") {
            $class = ($arr['class'] == "" || empty($arr['class'])) ? "php" : $arr['class'];
            return str_replace(array("{{ClassName}}", "{{MethodName}}"), array($class, $arr['method']), $string);
        } else {
            return $call;
        }
    }

    /**
     * @return bool
     */
    private static function requiresDelegateToOriginalPrependFile()
    {
        return ini_get('stackify.auto_prepend_library') &&
            stackify_prepend_overwritten() &&
            ini_get("auto_prepend_file") &&
            file_exists(stream_resolve_include_path(ini_get("auto_prepend_file")));
    }

    /**
     * Watch a function for calls and create timeline spans around it.
     *
     * @param string $function
     * @param string $category
     */
    public static function watch($function, $category = null)
    {
        if (!isset(self::$defaultOptions['watches'][$function])) { // not watched?
            self::$defaultOptions['watches'][$function] = $category;
            if (!self::$stackifyExtension->watchSpan($function, $category)) {
                self::log(1, "Unable to watch function: $function, something went wrong with the extension.");
            }
        }
    }

    /**
     * Log a message to the file defined in $errorLog
     *
     * @param int $level Logs message level. 1 = warning, 2 = info, 3 = debug
     * @param string $message
     * @return void
     */
    public static function log($level, $message)
    {
        try {
            if (self::$errorLogFile === null) {
                $errorLogFileWritable = @touch(self::$errorLog);

                if (self::$logFilePathWritable) {
                    if ($errorLogFileWritable === false) {
                        self::phpErrorLog(1, 'Stackify\Profiler::log() - Unable to create the log file: stackify-php-apm.log');
                    } else if (@chmod(self::$errorLog, 0777) === false) {
                        self::phpErrorLog(1, 'Stackify\Profiler::log() - Unable to permissions of the log file: stackify-php-apm.log');
                    }
                }

                self::$errorLogFile = $errorLogFileWritable;
            }

            if (self::$errorLogFile === true) {
                self::stackifyLog($level, $message);
            } else {
                self::phpErrorLog($level, $message);
            }
        } catch (\Exception $ex) {
            $errorLogFile = false;
            self::phpErrorLog(1, 'Unable able to log error to stackify-php-apm.log - '.$ex->getMessage());
        }
    }

    /**
     * Log message to stackify php apm log
     * @param int $level
     * @param string $message
     *
     * @return bool
     */
    private static function stackifyLog($level, $message)
    {
        $t = microtime(true);
        $ms = sprintf("%03d",($t - floor($t)) * 1000);
        $level = ($level === 3) ? "DEBUG" : (($level === 2) ? "INFO" : "WARN");
        return error_log(sprintf('%s %s [Stackify] - %s '.PHP_EOL, date('Y-m-d H:i:s,'.$ms), $level, $message), 3, self::$errorLog);
    }

    /**
     * Log message to php error log
     * @param int $level
     * @param string $message
     *
     * @return bool
     */
    private static function phpErrorLog($level, $message)
    {
        $t = microtime(true);
        $ms = sprintf("%03d",($t - floor($t)) * 1000);
        $level = ($level === 3) ? "DEBUG" : (($level === 2) ? "INFO" : "WARN");
        return error_log(sprintf('%s %s [Stackify] - %s', date('Y-m-d H:i:s,'.$ms), $level, $message), 0);
    }
}

// auto-starts the profiler if that is configured
\Stackify\Profiler::autoStart();
