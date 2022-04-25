<?php

/*
 * The Software is provided to you by the Licensor under the License,
 * as defined below, subject to the following condition.
 *
 * Without limiting other conditions in the License,
 * the grant of rights under the License will not include,
 * and the License does not grant to you, the right to Sell the Software.
 *
 * For purposes of the foregoing, "Sell" means practicing any or all of the rights
 * granted to you under the License to provide to third parties,
 * for a fee or other consideration (including without limitation fees for hosting
 * or consulting / support services related to the Software),
 * a product or service whose value derives, entirely or substantially,
 * from the functionality of the Software.
 * Any license notice or attribution required by the License must also include
 * this Commons Clause License Condition notice.
 *
 * * Software: GTD - Git Tug Deployer
 * * License: Apache 2.0
 * * Licensor: David Mougel <david@barbichette.net>
 */

// =============================================================================

ini_set('display_errors', true);
ini_set('display_startup_errors', true);
ini_set('html_errors', false);
error_reporting(E_ALL);

ini_set('max_execution_time', '1800');

// =============================================================================

class GTD
{

    // =========================================================================

    const HOOK_KEY_PARAM            = 'hk';

    const GEN_KEYS_NB               = 32;
    const GEN_KEYS_LENGTH           = 64;
    const GEN_KEYS_ALPHABET         = 'abcdefghijklmnopqrstuvwxyz'
                                    . 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                                    . '0123456789'
                                    . '$%#~@+!*';

    const PLATFORM_SHOULD_PROCESS   = 'should_process';
    const PLATFORM_NOT_MATCHING     = 'not_matching';
    const PLATFORM_MALFORMED        = 'malformed';
    const PLATFORM_USER_NOT_ALLOWED = 'user_not_allowed';
    const PLATFORM_NO_CHANGE        = 'no_change';

    const LOG_LEVEL_INFO            = 'info';
    const LOG_LEVEL_WARNING         = 'warning';
    const LOG_LEVEL_ERROR           = 'error';
    const LOG_LEVEL_SUCCESS         = 'success';

    // =========================================================================

    private static $instance;

    public static function setup()
    {
        if (self::$instance === null) self::$instance = new self();
        return self::$instance;
    }

    // =========================================================================

    private $rootDir;
    private $config;
    private $ctx;

    private $platformData;

    public function __construct()
    {
        $this->ctx = php_sapi_name() === 'cli' ? 'cli' : 'web';

        $this->rootDir = __DIR__;
        $this->loadConfiguration();

        if ($this->ctx === 'cli') {
            $this->cli();
            exit;
        }

        if (array_key_exists('nothing', $_GET)) {
            exit;
        }

        if (array_key_exists('d', $_GET) && ($fn = trim($_GET['d']))) {
            if (!method_exists($this, $fn = 'do___' . $fn)) {
                $this->renderError("Invalid action", [ 'function' => $fn ]);
            }

            $this->$fn();
            exit;
        }

        if (array_key_exists(self::HOOK_KEY_PARAM, $_GET)) {
            $this->processHookRequest($_GET[self::HOOK_KEY_PARAM],
                array_key_exists('f', $_GET) ? ($_GET['f'] === 'y') : false,
                array_key_exists('s', $_GET) ? ($_GET['s'] === 'y') : false);
            exit;
        }

        $this->render();
        exit;
    }

    // =========================================================================
    // AUTHENTICATION

    /**
     * Get/Set current login
     * @param  mixed $login NULL to get current, false to logout, or stdObject of username/password combination
     * @return mixed The currently logged-in stdObject, or NULL if logged out
     */
    public function getCurrentLogin($login = null)
    {
        $combine = function($login)
        {
            return hash('sha256', $login->username
                . hash('sha256', $login->username . ':' . $login->password)
                . $login->password);
        };

        $k = 'GTD_AUTH';
        if ($login === null) {
            if (!array_key_exists($k, $_COOKIE) || !$_COOKIE[$k]) return;
            foreach ($this->cfg('web.login') as $login) {
                if ($combine($login) === $_COOKIE[$k]) {
                    return $login;
                }
            }
        }

        if ($login === false) {
            setcookie($k, '', time() - (3600 * 24), '/', '', false, false);
            return;
        }

        setcookie($k, $combine($login),
            time() + (3600 * 24 * 365), '/', '', false, false);

        return $this->getCurrentLogin();
    }

    public function setCurrentLogin($login)
    {
        $this->getCurrentLogin($login);
    }

    // =========================================================================
    // LOG

    public function getLogFile(DateTime $dt = null)
    {
        if (!$this->cfg('log.enabled')) return;
        $path = $this->joinPath($this->cfg('log.directory'), $this->cfg('log.file_name'));
        if ($dt === null) $dt = new DateTime();
        if (preg_match_all('/\{d:([a-z])\}/i', $path, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $m) $path = str_replace($m[0], $dt->format($m[1]), $path);
        }
        return $path;
    }

    public function log($str, $type = self::LOG_LEVEL_INFO)
    {
        $dt = new DateTime();
        if (!($path = $this->getLogFile($dt))) return;

        $origin = 'CLI';
        if ($this->ctx === 'web') {
            $origin = (array_key_exists('REMOTE_ADDR', $_SERVER) && ($ip = $_SERVER['REMOTE_ADDR'])) ? $ip : '?';
        }

        $str = $dt->format('Y-m-d H:i:s')
            . ' [' . strtoupper($type) . ']'
            . ' (' . $origin . ')'
            . ' ' . $str
            . "\n";

        if (!(is_dir($dir = dirname($path)))) mkdir($dir, 0755, true);
        $handle = fopen($path, 'a');
        fwrite($handle, $str);
        fclose($handle);
    }

    public function readLog(DateTime $dt = null, $offset = 0, $length = null)
    {
        $lf = '{~§~}';
        if (!($path = $this->getLogFile($dt))) return [];
        if (!is_file($path)) return [];
        if (!($raw = trim(file_get_contents($path)))) return [];

        // We replace lines feeds by a known character sequence.
        $raw = preg_replace("/\s*\n(?![0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})/", $lf . '$1', $raw);

        if (!($lines = explode("\n", $raw))) return [];
        if (!array_key_exists($offset, $lines)) return [];
        if ($offset !== 0 || $length !== null) $lines = array_slice($lines, $offset, $length);

        $idx = $offset;
        return array_values(array_filter(array_map(function($line) use ($lf, &$idx)
        {
            if (!preg_match('/^([0-9 :-]{19})\s*\[([^\]]+)\]\s*(.*)$/', trim($line), $m)) return;
            return (object) [
                'idx'  => $idx++,
                'at'   => $m[1],
                'type' => $m[2],
                'str'  => trim(str_replace($lf, "\n", $m[3])),
            ];
        }, $lines)));
    }

    // =========================================================================
    // CONTROLLERS

    public function do___logout()
    {
        $this->setCurrentLogin(false);
        header('Location: ./index.php');
        exit;
    }

    public function do___genKeys()
    {
        header('Content-type: text/plain; charset=utf-8');
        $a = self::GEN_KEYS_ALPHABET;
        $aLength = strlen($a);
        for ($i = 0; $i < self::GEN_KEYS_NB; $i++) {
            $k = '';
            for ($j = 0; $j < self::GEN_KEYS_LENGTH; $j++) $k .= $a[mt_rand(0, $aLength - 1)];
            echo $k . "\n";
        }
    }

    public function do___getLog()
    {
        $offset = array_key_exists('offset', $_GET) ? ((int) $_GET['offset']) : 0;
        $length = array_key_exists('length', $_GET) ? (((int) $_GET['length']) ?: null) : null;

        $this->success([ 'log' => $this->readLog(null, $offset, $length) ]);
    }

    // -------------------------------------------------------------------------

    public function cli($argv = null)
    {
        $daemonServicePath = $_SERVER['HOME'] . '/.config/systemd/user/gtd.service';
        $isRootUser = ((int) posix_getuid()) === 0;
        $assertRootUser = function() use ($isRootUser) {
            if ($isRootUser) return;
            die("You must run this command with root privileges.\n");
        };

        $contexts = [

            'cmd' => [

                'exec' => function() use ($daemonServicePath, $assertRootUser)
                {
                    if ($this->getDaemonPullRequestStatus()) {
                        $response = $this->executeHook();
                        $this->log('Executed the pool from the cmd. Response >>' . "\n" . $response . "\n");
                        $this->setDaemonPullRequestStatus(false);
                    }
                },

            ],

            'daemon' => [

                'enable' => function() use ($daemonServicePath, $assertRootUser)
                {
                    if (is_file($daemonServicePath)) die("Daemon service seems to exists. Please disable it first.\n");
                    if (!is_dir($daemonServiceDir = dirname($daemonServicePath))) mkdir($daemonServiceDir, 0755, true);

                    echo "Creating systemd service file (${daemonServicePath})...\n";
                    file_put_contents($daemonServicePath, implode("\n", [
                        '[Unit]',
                        'Description=Git Tug Deployer',
                        'After=network.target',
                        '',
                        '[Service]',
                        'Type=simple',
                        'Environment="GTD_DAEMON_GIT_BRANCH=' . $this->cfg('git.branch') . '"',
                        'ExecStart=' . $this->joinPath($this->rootDir, 'gtd') . ' daemon watch',
                        '',
                        '[Install]',
                        'WantedBy=timers.target',
                    ]));
                    chmod($daemonServicePath, 0755);

                    echo "Enabling 'gtd' systemd service...\n";
                    echo '>> ' . (trim(shell_exec('systemctl --user enable gtd 2>&1') ?: '') ?: '(nothing)') . "\n";

                    echo "Starting 'gtd' systemd service...\n";
                    echo '>> ' . (trim(shell_exec('systemctl --user start gtd 2>&1') ?: '') ?: '(nothing)') . "\n";
                    echo "Getting status of 'gtd' systemd service...\n";
                    echo '>> ' . (trim(shell_exec('systemctl --user status gtd 2>&1') ?: '') ?: '(nothing)') . "\n";

                    $this->log('Enabled daemon');

                    echo "Done.\n";
                },

                'disable' => function() use ($daemonServicePath, $assertRootUser)
                {
                    echo "Stopping 'gtd' systemd service...\n";
                    echo '>> ' . (trim(shell_exec('systemctl --user stop gtd 2>&1') ?: '') ?: '(nothing)') . "\n";
                    echo "Disabling 'gtd' systemd service...\n";
                    echo '>> ' . (trim(shell_exec('systemctl --user disable gtd 2>&1') ?: '') ?: '(nothing)') . "\n";
                    echo "Removing systemd service file...\n";
                    if (is_file($daemonServicePath)) unlink($daemonServicePath);

                    $this->log('Disabled daemon');

                    echo "Done.\n";
                },

                'reload' => function()
                {
                    $this->cli(['daemon', 'disable']);
                    $this->cli(['daemon', 'enable']);
                },

                'watch' => function()
                {
                    $this->log('Started daemon');

                    while (true) {
                        if ($this->getDaemonPullRequestStatus()) {
                            $response = $this->executeHook();
                            $this->log('Executed the pool from the daemon. Response >>' . "\n" . $response . "\n");
                            $this->setDaemonPullRequestStatus(false);
                        }

                        sleep(2);
                    }
                },

            ],
        ];

        if ($argv === null) {
            $argv = $_SERVER['argv'];
            array_shift($argv);
        }

        if (count($argv) < 2) {
            echo "Available commands:\n";
            foreach ($contexts as $contextName => $commands) {
                foreach ($commands as $commandName => $commandFunc) {
                    echo "  - ${contextName} ${commandName}\n";
                }
            }
            exit;
        }

        if (!array_key_exists($contextName = array_shift($argv), $contexts)) die("Unknown context '${contextName}'.\n");
        if (!array_key_exists($commandName = array_shift($argv), $contexts[$contextName])) die("Unknown command '${commandName}' in context '${contextName}'.\n");

        $contexts[$contextName][$commandName]();
    }

    // =========================================================================
    // RENDERING/OUTPUT

    public function renderError($message, array $data = [])
    {
        echo '<strong>' . $message . '</strong>';
        exit;
    }

    public function output(array $data = [])
    {
        header('Content-type: text/javascript; charset=utf-8');
        echo json_encode($data, JSON_PRETTY_PRINT);
        exit;
    }

    public function success(array $data = [])
    {
        $this->output(array_merge($data, [
            'success' => true,
        ]));
    }

    public function error($code, array $data = [])
    {
        $this->output(array_merge($data, [
            'success' => false,
            'error'   => $code,
        ]));
    }

    // =========================================================================
    // HOOK/GIT FUNCTIONS

    public function getHookTargetUrl($lookupKey = null, $lookupHash = null)
    {
        $byKey = [];
        $byHash = [];
        $hashMethod = $this->cfg('security.hash_method');
        foreach ($this->cfg('security.hook_keys') as $k) {
            $hash = hash($hashMethod, $k);
            $url = $_SERVER['REQUEST_SCHEME'] . '://'
                . $_SERVER['HTTP_HOST']
                . rtrim($_SERVER['REQUEST_URI'], '/')
                . '/index.php?' . self::HOOK_KEY_PARAM . '=' . $hash;

            $byKey[$k] = $url;
            $byHash[$hash] = (object) [ 'key' => $k, 'url' => $url ];
        }

        if ($lookupHash) return array_key_exists($lookupHash, $byHash) ? $byHash[$lookupHash] : null;
        if ($lookupKey === null) return $byKey;
        if (!array_key_exists($lookupKey, $byKey)) return false;
        return $byKey[$lookupKey];
    }

    public function processHookRequest($hookKeyHash, $forced = false, $silent = false)
    {
        if (!($hook = $this->getHookTargetUrl(null, $hookKeyHash))) {
            $this->log('(PHR) Invalid hook key: ' . $hookKeyHash);
            if (!$silent) $this->error('invalid_hook_key');
            return;
        }

        if ($forced) {
            if ($this->cfg('daemon.enabled')) {
                $this->setDaemonPullRequestStatus(true);
                $response = 'PULL_REQUEST_SET';
            } else {
                $response = $this->executeHook();
            }

            $this->log('(PHR) Executed a forced Pull/Pull-Request with response: ' . $response);
            if (!$silent) $this->success([ 'forced' => $forced, 'response' => $response ]);
            return;
        }

        $changeBranch = $this->cfg('git.branch');
        $commitMessagePattern = $this->cfg('git.commit_message_pattern');

        $this->platformData = null;
        $foundPlatform = null;
        foreach ([ 'bitbucket', 'github' ] as $platformName) {
            $platformProcess = $this->{'processHookPlatform__' . $platformName}($changeBranch, $commitMessagePattern);
            if ($platformProcess === self::PLATFORM_NOT_MATCHING) continue;

            if ($platformProcess !== self::PLATFORM_SHOULD_PROCESS) {
                if (!$silent) {
                    $this->error('platform_error', [
                        'process_code' => $platformProcess,
                        'process_data' => $this->platformData,
                    ]);
                }
                return;
            }

            $foundPlatform = $platformName;
            break;
        }

        if (!$foundPlatform) {
            $this->log('(PHR) No platform matching with request');
            if (!$silent) $this->error('no_platform_matching_with_request');
            return;
        }

        $this->log('(PHR) Platform matched: ' . $foundPlatform);

        if ($this->cfg('daemon.enabled')) {
            $this->setDaemonPullRequestStatus(true);
            $response = 'PULL_REQUEST_SET';
        } else {
            $response = $this->executeHook();
        }

        $this->log('(PHR) Pull/Pull-Request response: ' . $response);

        if ($silent) return;
        $this->success([
            'platform' => $foundPlatform,
            'process_data' => $this->platformData,
            'response' => $response,
        ]);
    }

    public function setDaemonPullRequestStatus($needsPull)
    {
        $this->log('(PHR) Set Pull-Request status: ' . ($needsPull ? 'TRUE' : 'FALSE'));
        file_put_contents($this->cfg('daemon.pull_request_path'), json_encode([
            'needs_pull' => $needsPull === true,
            'at'         => (new DateTime())->format('Y-m-d H:i:s'),
        ], JSON_PRETTY_PRINT));
    }

    public function getDaemonPullRequestStatus()
    {
        if (!is_file($path = $this->cfg('daemon.pull_request_path'))) return false;
        if (!($raw = file_get_contents($path))) return false;
        if (!($json = json_decode($raw))) return false;
        return property_exists($json, 'needs_pull') && $json->needs_pull;
    }

    public function executeHook()
    {
        return $this->git('pull');
    }

    public function processHookPlatform__bitbucket($changeBranch, $commitMessagePattern)
    {
        $pl = @file_get_contents('php://input');
        if (!$pl = @json_decode($pl)) return self::PLATFORM_NOT_MATCHING;
        if (!is_object($pl)) return self::PLATFORM_NOT_MATCHING;
        if ($this->prop($pl, 'actor', 'type') !== 'user') return self::PLATFORM_NOT_MATCHING;
        if (!($actorLink = $this->prop($pl, 'actor', 'links', 'self', 'href'))) return self::PLATFORM_NOT_MATCHING;
        if (!preg_match('/^https?:\/\/([^\/]+\.)?bitbucket\.org\/.*/', $actorLink)) return self::PLATFORM_NOT_MATCHING;

        // At this point, we do not return 'not matching' anymore.
        // This is obviously BitBucket.
        $this->platformData = $pl;

        if (!($actorNickname = $this->prop($pl, 'actor', 'nickname'))) return self::PLATFORM_MALFORMED;
        if ($this->cfg('git.restrict_users') && !in_array('bitbucket:' . $actorNickname, $this->cfg('git.allowed_users'))) return self::PLATFORM_USER_NOT_ALLOWED;
        if (!is_array($changes = $this->prop($pl, 'push', 'changes'))) return self::PLATFORM_NO_CHANGE;

        $changeMatched = false;
        foreach ($this->prop($pl, 'push', 'changes') ?: [] as $change) {
            if ($this->prop($change, 'new', 'type') !== 'branch') continue;
            if ($this->prop($change, 'new', 'name') !== $changeBranch) continue;
            $msg = trim($this->prop($change, 'new', 'target', 'summary', 'raw') ?: '');
            if (!preg_match($commitMessagePattern, $msg)) continue;
            $changeMatched = true;
            break;
        }

        if ($changeMatched) return self::PLATFORM_SHOULD_PROCESS;
        return self::PLATFORM_NO_CHANGE;
    }

    public function processHookPlatform__github($changeBranch, $commitMessagePattern)
    {
        return self::PLATFORM_NOT_MATCHING;
    }

    public function git($command)
    {
        $binary = $this->cfg('git.binary_path');
        $prefix = '';

        if ($sshKeyPath = $this->cfg('git.use_ssh_key')) {
            $prefix = "GIT_SSH_COMMAND='ssh -i ${sshKeyPath} -o IdentitiesOnly=yes' ";
        }

        $fullCommand = $prefix . $binary . ' ' . $command . ' 2>&1';
        chdir($this->cfg('repository.root_directory'));
        return trim(shell_exec($fullCommand));
    }

    public function gitBranch()
    {
        return $this->git('rev-parse --abbrev-ref HEAD');
    }

    public function gitRepositoryUrl()
    {
        return $this->git('config --get remote.origin.url');
    }

    public function getLastCommit($asString = false)
    {
        if (!(preg_match('/^commit\s([a-f0-9]+)\n+author:\s*([^\n]*)\n+date:\s*([^\n]*)\n+(.+)$/imsU', trim($this->git('log -1')), $m))) return null;
        return (object) [
            'uid'     => trim($m[1]),
            'author'  => trim($m[2]),
            'date'    => trim($m[3]),
            'comment' => trim($m[4]),
        ];
    }

    // UTILS

    public function prop($obj)
    {
        $args = func_get_args();
        $obj = array_shift($args);
        foreach ($args as $arg) {
            if (!is_object($obj) && !is_array($obj)) return false;
            if (is_object($obj) && !property_exists($obj, $arg)) return false;
            else { $obj = $obj->$arg; continue; }
            if (is_array($obj) && !array_key_exists($arg, $obj)) return false;
            else { $obj = $obj[$arg]; continue; }
        }
        return $obj;
    }

    private function joinPath()
    {
        $path = '';
        foreach (func_get_args() as $part) {
            if ($path !== '') $path .= DIRECTORY_SEPARATOR;
            $path .= rtrim($part, '/\\');
        }
        return $path;
    }

    // CONFIG

    public function cfg($k = null, $raw = false)
    {
        if ($k === null) return $this->config;
        if (!array_key_exists($k, $this->config)) {
            $this->renderError("Trying to get invalid configuration key", [ 'key' => $k ]);
        }

        $v = $this->config[$k];
        if ($raw) return $v;
        if (is_string($v)) {
            if (strtolower($v) === 'on' || $v === '1') $v = true;
            else if (strtolower($v) === 'off' || $v == '0') $v = false;
            else if ($k === 'git.branch' && array_key_exists('GTD_DAEMON_GIT_BRANCH', $_SERVER)) $v = $_SERVER['GTD_DAEMON_GIT_BRANCH'];
            else {
                $v = str_replace('{gtd_root}', $this->rootDir, $v);
                if (preg_match_all('/\{env:([^}]+)\}/i', $v, $matches, PREG_SET_ORDER)) {
                    foreach ($matches as $m) {
                        $v = str_replace($m[0], array_key_exists($m[1], $_SERVER) ? $_SERVER[$m[1]] : '', $v);
                    }
                }
            }

            if ((strpos($v, DIRECTORY_SEPARATOR . '..') !== false
                || strpos($v, '..' . DIRECTORY_SEPARATOR) !== false)
                    && file_exists($v)) $v = realpath($v);
        }
        return $v;
    }

    public function loadConfiguration()
    {
        if (!is_file($path = $this->joinPath($this->rootDir, 'config.ini'))) {
            $this->renderError("Configuration file is missing", [ 'path' => $path ]);
        }

        $this->config = array_merge([

            'gtd.enabled'                 => 'off',

            'repository.root_directory'   => null,

            'security.hook_keys'          => [],
            'security.hash_method'        => null,

            'daemon.enabled'              => 'off',
            'daemon.pull_request_path'    => null,
            'daemon.run_as'               => null,

            'git.binary_path'             => null,
            'git.use_ssh_key'             => 'off',
            'git.branch'                  => null,
            'git.commit_message_pattern'  => null,
            'git.restrict_users'          => 'on',
            'git.allowed_users'           => [],

            'log.enabled'                 => 'off',
            'log.directory'               => null,
            'log.file_name'               => null,
            'log.web_refresh_delay'       => 5,

            'web.enabled'                 => 'off',
            'web.login'                   => [],

        ], parse_ini_file($path));

        foreach ($this->config['web.login'] as $i => $v) {
            $cols = explode(':', $v, 2);
            $this->config['web.login'][$i] = (object) [
                'username' => $cols[0],
                'password' => $cols[1],
            ];
        }


        $issues = [];

        $repositoryRoot = $this->cfg('repository.root_directory');
        if (!is_dir($repositoryRoot)) $issues[] = "Root directory of the repository doesn't seems to exist (${repositoryRoot}).";
        else if (!is_dir($this->joinPath($repositoryRoot, '.git'))) $issues[] = "Root directory is not a valid Git Repository (${repositoryRoot}).";
        else if ($this->ctx === 'web' && !is_writable($repositoryRoot)) $issues[] = "Root directory is not writable for the current user (${repositoryRoot}).";

        if ($this->cfg('daemon.enabled') === true) {
            if (!($prPath = $this->cfg('daemon.pull_request_path'))) $issues[] = "The daemon is enabled without a path for the pull requests.";
            else if (is_file($prPath)) {
                if (!is_writable($prPath)) $issues[] = "The daemon is enabled with a non-writable file path.";
            } else if (!is_writable(dirname($prPath))) $issues[] = "The daemon is enabled with a non-writeable directory for the non-existing file path.";
            if (!$this->cfg('daemon.run_as')) $issues[] = "The user which one the daemon will be executed has to be specified.";
        }

        if (!in_array($this->cfg('security.hash_method'), $algos = hash_algos())) {
            $issues[] = "Hash method is not a valid algorithm in this environment. Valid are: " . implode(', ', $algos) . ").";
        }

        $binPath = $this->cfg('git.binary_path');
        if (!is_file($binPath)) $issues[] = "The Git binary path doesn't seems to be a valid path file.";
        else if (!is_executable($binPath)) $issues[] = "The Git binary path cannot be executed (probably chmod +x is not applyed for the PHP user).";

        if (($sshKeyPath = $this->cfg('git.use_ssh_key')) !== false) {
            if (!is_file($sshKeyPath)) $issues[] = "The SSH Key Path is not a valid file.";
            else if (!is_readable($sshKeyPath)) $issues[] = "The SSH Key is not readable. Think about a '$ chmod +r ${sshKeyPath}'.";
        }

        if (!$this->cfg('git.branch')) $issues[] = "The branch is empty.";

        set_error_handler(function() {}, E_WARNING);
        $regexError = preg_match($this->cfg('git.commit_message_pattern'), '') === false;
        restore_error_handler();
        if ($regexError) $issues[] = "The commit message pattern is not a valid regular expression.";

        if ($this->cfg('git.restrict_users') && !$this->cfg('git.allowed_users')) {
            $issues[] = "Restricting by user, but no user allowed.";
        }

        if ($issues) {
            header('Content-type: text/plain; charset=utf-8');
            echo "### Some issues in the configuration file where encountered ###\n\n";
            echo '>> ' . implode("\n\n>> ", $issues) . "\n";
            exit;
        }

        return $this;
    }

    // =========================================================================
    // HTML TEMPLATE

    public function render()
    {
        $auth = (object) [
            'as'      => $this->getCurrentLogin(),
            'info'    => null,
            'error'   => array_key_exists('_aerr', $_GET) ? $_GET['_aerr'] : null,
            'default' => (object) [ 'username' => null, 'password' => null ],
        ];

        if (array_key_exists('_a', $_POST) && is_array($auth->info = $_POST['_a'])) {
            $auth->info = (object) array_merge(array_fill_keys(['u', 'p', 'qk', 'qa'], null), $auth->info);
            if (!$auth->info->u) $auth->error = "Le nom d'utilisateur est manquant";
            else if (!$auth->info->p) $auth->error = "Le mot de passe est manquant";
            else {
                $found = false;
                foreach ($this->cfg('web.login') as $login) {
                    if ($login->username !== $auth->info->u) continue;
                    if ($login->password !== $auth->info->p) continue;
                    $this->setCurrentLogin($login);
                    $found = true;
                }
                if (!$found) $auth->error = "Nom d'utilisateur ou mot de passe invalide";
            }
            header('Location: ./index.php' . ($auth->error ? '?_aerr=' . urlencode($auth->error ?: "Erreur inconnue") : ''));
            exit;
        }

        if (!$auth->as && $this->cfg('web.auto_fill_login')) {
            foreach ($this->cfg('web.login') as $login) {
                $auth->default = $login;
                break;
            }
        }

        ?>
<!doctype html>
<html lang="en">

  <head>

    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <link rel="preconnect" href="https://fonts.gstatic.com">
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons+Outlined" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;700&display=swap" rel="stylesheet">

    <title>&rarr; Git Tug Deployer &larr;</title>

    <style>

        :root {

            --font-size: 15px;

            --default-text-color: #eee;
            --highlight-color: #ccee00;
            --dark-highlight-color: #88aa00;
            --discret-highlight-color: #525828;
            --transparent-highlight-color: #ccee0044;
            --page-bg-color: #333;
            --header-bg-color: #222;
            --header-fg-color: #333;
            --danger-color: #ff3333;
            --dark-danger-color: #cc0000;

            --label-width: 200px;

            font-size: var(--font-size);

        }

        * { transition: all .125s; }

        ::selection { background: var(--highlight-color); color: black; }

        .material-icons-outlined { margin-top: -.2em; vertical-align: middle; font-size: 1.5em; }

        body, input, pre, button, code { font-family: "IBM Plex Mono"; font-size: 1rem; }
        body { margin: 0; background: var(--page-bg-color); user-select: none; cursor: default; }
        body.body-logged-in { border-bottom: 200px solid var(--discret-highlight-color); box-shadow: 0 -1px 0 var(--highlight-color) inset; }
        body.is-loading:after { display: block; position: fixed; left: 0; right: 0; top: 0; bottom: 0; background: var(--discret-highlight-color); content: ""; opacity: .25; z-index: 999; }
        header { padding: 3vh 0 0 0; background: var(--header-bg-color); border-bottom: 10px solid var(--highlight-color); color: var(--header-fg-color); }
        header > pre { display: table; position: relative; margin: 0 auto 0 auto; }
        header > p { display: block; position: relative; margin: 3vh 0 0 0; padding: 2vh 40px 2vh 0; border-top: 1px solid var(--highlight-color); color: var(--highlight-color); text-transform: uppercase; text-align: center; letter-spacing: .08rem; }
        header > p em { font-style: normal; }
        header > p > a { display: inline; margin: 0 0 0 20px; padding: 5px 5px 5px 9px; background: #ffffff11; color: var(--danger-color); text-decoration: none; }
        header > p > a:hover { color: white; }
        header > p > a > .material-icons-outlined { margin-left: -5px; font-size: 1.3em; opacity: .5; }

        p:first-child, ul:first-child, li:first-child { margin-top: 0; }
        p:last-child, ul:last-child, li:last-child { margin-bottom: 0; }

        hr { margin: 20px 0; width: 100px; height: 3px; background: var(--highlight-color); border: none; outline: none; opacity: .3; }
        code { padding: 0 3px; background: #ffffff22; user-select: all; }
        blockquote { margin: 0; padding: 20px; background: #ffffff11; border-left: 1px solid var(--highlight-color); }
        blockquote hr { width: auto; background: #ffffff33; }
        ul, ol { margin-left: 0; padding-left: 1.2rem; }
        ul { list-style-type: "- "; }
        u { color: var(--highlight-color); user-select: all; }
        i { display: inline-block; margin: 2px 0; padding: 3px 5px; border: 1px dashed #ffffff33; font-style: normal; }
        i .material-icons-outlined { font-size: 1em; }
        i a { text-decoration: none; }
        a { color: var(--highlight-color); text-decoration: underline; }
        a:hover { color: var(--dark-highlight-color); text-decoration: none; }

        .input, .button { display: block; box-sizing: border-box; appearance: none; padding: 8px; border-radius: 0; outline: none; color: white; }
        .input { background: var(--header-bg-color); border: 1px dashed var(--highlight-color); }
        .input:hover, .input:focus { background: var(--header-fg-color); }
        .button { padding-top: 9px; padding-bottom: 9px; background: var(--highlight-color); border: 10px solid var(--dark-highlight-color); border-top: none; border-bottom: none; color: black; text-decoration: none; cursor: default; }
        .button:hover { border-color: var(--highlight-color); }
        .button.button-small { display: inline-block; padding: 5px 6px; }

        .field { display: flex; margin: 0 0 10px 0; }
        .field > .label { display: block; flex: 0 0 var(--label-width); padding: 9px 8px 0 0; color: white; text-align: right; }
        .field > .label:after { float: right; margin: -.4em 0 0 .2em; content: "\2192"; font-size: 1.7em; opacity: .3; }
        .field > .input { flex: 1; }

        .inline-error, .error { color: var(--danger-color); }
        .error { margin: 10px 0 0 0; padding: 9px; background: var(--header-bg-color); border: 1px dashed var(--dark-danger-color); }

        .with-fields { margin-left: calc(var(--label-width) + 8px); }

        .wrapper { margin: 40px auto 40px auto; padding: 0 40px; max-width: 888px; color: var(--default-text-color); }
        .wrapper.large { max-width: 1111px; }

        #section-log { position: relative; background: var(--discret-highlight-color); border-bottom: 1px solid var(--highlight-color); opacity: .5; }
        #section-log:hover { opacity: 1; }
        #section-log > .wrapper { margin-top: 0; margin-bottom: 0; }
        #section-log > .wrapper > strong { display: none; }
        #section-log > .wrapper > #log-items { overflow-x: hidden; overflow-y: scroll; height: 200px; }

        #section-log > .wrapper > #log-items::-webkit-scrollbar { width: 8px; height: 8px: }
        #section-log > .wrapper > #log-items::-webkit-scrollbar-track { background-color: #ffffff44; }
        #section-log > .wrapper > #log-items::-webkit-scrollbar-thumb { background: white; }

        #section-log > .wrapper > #log-items > div { display: flex; border-bottom: 1px solid #ffffff33; }
        #section-log > .wrapper > #log-items > div:last-child { border-bottom: none; }
        #section-log > .wrapper > #log-items > div.is-new { background: var(--transparent-highlight-color); }
        #section-log > .wrapper > #log-items > div > * { padding: 3px 5px; }
        #section-log > .wrapper > #log-items > div > strong { flex: 0 0 185px; font-weight: normal; }
        #section-log > .wrapper > #log-items > div > em { flex: 0 0 80px; font-style: normal; }
        #section-log > .wrapper > #log-items > div > div { padding-right: 15px; }

        #section-log > #log-progress { position: absolute; left: 0; top: calc(100% + 1px); width: 0; height: 2px; background: var(--highlight-color); transition: none; }

        .cta { padding: 20px; background: #ffffff11; border: 1px solid var(--highlight-color); }
        .cta .button { display: inline-block; padding: 12px 11px; font-weight: bold; }

        #inner-frame-container { display: none; position: fixed; right: 0; top: 0; bottom: 0; width: 33%; background: var(--header-bg-color); border-left: 1px solid var(--highlight-color); z-index: 99; }
        #inner-frame-container.shown { display: block; }
        #inner-frame-container:before { display: block; position: absolute; right: calc(100% + 1px); top: 0; bottom: 0; width: 100vw; background: var(--discret-highlight-color); opacity: .5; content: ""; }
        #inner-frame-container:after { display: block; position: absolute; right: 100%; bottom: 0; padding: 8px 0 8px 10px; background: var(--header-bg-color); border: 1px solid var(--highlight-color); border-right: none; border-bottom: none; color: #aaa; content: "Fermer"; text-transform: uppercase; }
        #inner-frame-container > iframe { display: block; box-sizing: border-box; position: absolute; left: 30px; top: 30px; width: calc(100% - 60px); height: calc(100% - 60px); border: 1px solid var(--discret-highlight-color); outline: none; }

    </style>

    <link rel="icon" href="data:image/png;base64,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">

  </head>

  <body class="<?php echo $auth->as ? 'body-logged-in' : 'body-guest'; ?>">

    <header>
<pre>
      $$\           $$$$$$\ $$$$$$$$\ $$$$$$$\           $$\
      \$$\         $$  __$$\\__$$  __|$$  __$$\         $$  |
       \$$\        $$ /  \__|  $$ |   $$ |  $$ |       $$  /
$$$$$$\ \$$\       $$ |$$$$\   $$ |   $$ |  $$ |      $$  /$$$$$$\
\______|$$  |      $$ |\_$$ |  $$ |   $$ |  $$ |      \$$< \______|
       $$  /       $$ |  $$ |  $$ |   $$ |  $$ |       \$$\
      $$  /        \$$$$$$  |  $$ |   $$$$$$$  |        \$$\
      \__/          \______/   \__|   \_______/          \__|
</pre>
        <p>
            <strong>Git Tug Deployer</strong>
            <em>~ Web Console</em>
            <?php if ($auth->as): ?>
                <a href="./index.php?d=logout">
                    <em>Déconnexion</em>
                    <span class="material-icons-outlined">close</span>
                </a>
            <?php endif; ?>
        </p>
    </header>

    <?php if (!$auth->as): ?>

        <div class="wrapper">
            <div id="auth">
                <form action="./index.php" method="post">
                    <div class="field">
                        <label class="label">Nom d'utilisateur</label>
                        <input
                            type="text"
                            class="input"
                            name="_a[u]"
                            placeholder="(°~°)"
                            spellcheck="false"
                            value="<?php echo $auth->default->username ?: ''; ?>"
                            >
                    </div>
                    <div class="field">
                        <label class="label">Mot de passe</label>
                        <input
                            type="password"
                            class="input"
                            name="_a[p]"
                            placeholder="°x°"
                            value="<?php echo $auth->default->password ?: ''; ?>"
                            >
                    </div>
                    <button type="submit" class="button with-fields">
                        <span class="material-icons-outlined">login</span>
                        <strong>Identification</strong>
                    </button>
                    <?php if ($auth->error): ?>
                        <div class="error with-fields">
                            <?php echo $auth->error; ?>
                        </div>
                    <?php endif; ?>
                </form>
            </div>
        </div>

    <?php else: ?>

        <div id="section-log">
            <div class="wrapper large">
                <strong>Journal</strong>
                <div
                    id="log-items"
                    data-url="./index.php?d=getLog&offset={offset}&length={length}"
                    data-refresh-delay="<?php echo $this->cfg('log.web_refresh_delay'); ?>"
                    ></div>
            </div>
            <div id="log-progress"></div>
        </div>

        <div class="wrapper large">

            <?php if (!$this->cfg('gtd.enabled')): ?>

                <strong class="inline-error">GTD est désactivé.</strong>

            <?php else: ?>

                <p><strong>GTD est activé.</strong></p>

                <?php foreach ($this->getHookTargetUrl() as $k => $u): ?>
                    <hr>
                    <div class="cta">
                        <a href="<?php echo $u; ?>&f=y" target="innerframe" class="button">Déployer maintenant</a>
                        <p>
                            La première clé <code><?php echo $k; ?></code> sera utilisée.<br>
                            La mise en production sera forcée.
                        </p>
                    </div>
                <?php break; endforeach; ?>

                <hr>

                <blockquote>
                    <p>
                        Si cela n'est pas déjà fait, il vous faut <strong>configurer un hook</strong>
                        sur BitBucket ou sur GitHub.<br>
                        Ce hook doit pointer sur l'un des URL suivants :
                    </p>
                    <ul>
                        <?php foreach ($this->getHookTargetUrl() as $k => $u): ?>
                            <li>
                                <code><?php echo $k; ?></code>
                                <i>
                                    <span class="material-icons-outlined">notifications</span>
                                    <a href="<?php echo $u; ?>" target="innerframe">Verbose</a>
                                </i>
                                <i>
                                    <span class="material-icons-outlined">dark_mode</span>
                                    <a href="<?php echo $u . '&s=y'; ?>" target="innerframe">Silent</a>
                                </i>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                    <hr>
                    <p>
                        <a href="./index.php?d=genKeys" target="innerframe" class="button button-small">Générer des clés</a>
                        pour les insérer dans le fichier <code>config.ini</code>.
                    </p>
                </blockquote>

                <hr>

                <p>
                    Ensuite, lorsque
                    <?php if ($this->cfg('git.restrict_users')): ?>
                        <?php if ($allowedUsers = $this->cfg('git.allowed_users')): ?>
                            <strong>l'un des utilisateurs suivants :</strong>
                            <ul>
                                <?php foreach ($allowedUsers as $allowedUser): ?>
                                    <li><code><?php echo $allowedUser; ?></code></li>
                                <?php endforeach; ?>
                            </ul>
                        <?php else: ?>
                            <strong class="inline-error">personne</strong>
                        <?php endif; ?>
                    <?php else: ?>
                        <strong>tout le monde</strong>
                    <?php endif; ?>
                    réalisera le <code>push</code> d'un <code>commit</code><br>

                    <?php $commitPattern = $this->cfg('git.commit_message_pattern'); ?>
                    <?php if (preg_match($commitPattern, 'nothing interesting')): ?>
                        <strong>avec n'importe quel message</strong>
                    <?php else: ?>
                        <strong>avec un message correspondant à</strong>
                        <code><?php echo $commitPattern; ?></code>
                    <?php endif; ?>
                    <br>

                    sur la <strong>branche <code><?php echo $this->cfg('git.branch'); ?></code></strong>,<br>

                    alors, GTD sera appelé par le hook<br>
                    et le script exécutera <code>$ <strong><?php echo $this->cfg('git.binary_path'); ?></strong> pull</code><br>
                    dans le répertoire <code><?php echo $this->cfg('repository.root_directory'); ?></code>.
                </p>

                <?php $lastCommit = '(none)'; ?>
                <?php if ($commit = $this->getLastCommit(true)): ?>
                    <?php $lastCommit = '<br>' . implode("<br>", [
                        'Commit: <code>' . $commit->uid . '</code>',
                        'Date: <code>' . $commit->date . '</code>',
                        'Author: <code>' . htmlentities($commit->author, ENT_COMPAT, 'utf-8') . '</code>',
                        'Comment: <code>' . htmlentities($commit->comment, ENT_COMPAT, 'utf-8') . '</code>',
                    ]); ?>
                <?php endif; ?>

                <blockquote>
                    FYI, la configuration GIT du répertoire du dépôt est la suivante :
                    <ul>
                        <li><strong>Branche :</strong> <code><?php echo $this->gitBranch(); ?></code></li>
                        <li><strong>URL distant :</strong> <code><?php echo $this->gitRepositoryUrl(); ?></code></li>
                        <li><strong>Dernier commit :</strong> <?php echo $lastCommit; ?></li>
                    </ul>
                </blockquote>

                <hr>

                <p>
                    <strong>Ci-dessous, sont listés les liens permettant d'exécuter un "<code>pull</code>", avec la clé de votre choix.</strong><br>
                    Notez que la vérification du message de commit et de la branche ne seront pas réalisé avec ces liens. Ils servent avant tout à effectuer un "<code>pull</code>" manuel.<br>
                    Le paramètre "<code>f=y</code>" est ajouté à ces liens, pour forcer le "<code>pull</code>".<br>
                    <strong>N'utilisez pas ces liens dans les hooks de BitBucket ou de GitHub.</strong>
                </p>
                <ul>
                    <?php foreach ($this->getHookTargetUrl() as $k => $u): ?>
                        <li><a href="<?php echo $u; ?>&f=y" target="innerframe"><?php echo $k; ?></a></li>
                    <?php endforeach; ?>
                </ul>

            <?php endif; ?>

        </div>

        <div id="inner-frame-container">
            <iframe src="?nothing" name="innerframe"></iframe>
        </div>

        <script>

            (function() {
                const $logProgress = document.getElementById("log-progress");
                const $items = document.getElementById("log-items");
                const url = $items.getAttribute("data-url");
                const refreshDelay = $items.getAttribute("data-refresh-delay");
                let lastIdx = null;

                const add = function(line) {
                    const $line = document.createElement("div");
                    $items.appendChild($line);

                    const $at = document.createElement("strong");
                    $at.innerText = line.at;
                    $line.appendChild($at);

                    const $type = document.createElement("em");
                    $type.innerText = line.type;
                    $line.appendChild($type);

                    const $str = document.createElement("div");
                    $str.innerText = line.str;
                    $line.appendChild($str);

                    return $line;
                };

                const animationStepDelay = 20;
                const animationMaxIterations = (refreshDelay * 1000) / animationStepDelay;
                let isFirstUpdate = true;
                let animationReversed = true;
                let animationIterations = animationMaxIterations;

                const update = function() {
                    animationIterations++;

                    if (animationIterations <= animationMaxIterations) {
                        let w = (animationIterations / animationMaxIterations) * 100;
                        if (animationReversed) w = 100 - w;
                        $logProgress.style.width = Math.max(0, Math.min(100, w)) + "%";
                        iterateUpdateStep();
                        return;
                    }

                    $logProgress.style.width = animationReversed ? 0 : "100%";
                    animationIterations = -1;
                    animationReversed = !animationReversed;

                    const pagedUrl = url
                        .replace(/\{offset\}/, lastIdx === null ? 0 : lastIdx + 1)
                        .replace(/\{length\}/, 0);

                    fetch(pagedUrl)
                        .then((response) => { return response.json(); })
                        .then((data) => {
                            if (data.log.length) {
                                Array.prototype.forEach.call($items.children, function($item) {
                                    $item.classList.remove("is-new");
                                });

                                let $lastLine;
                                data.log.forEach((line) => {
                                    $lastLine = add(line);
                                    if (!isFirstUpdate) $lastLine.classList.add("is-new");
                                    lastIdx = line.idx;
                                });
                                $items.scrollTop = $lastLine.offsetTop + 1000;
                            }

                            isFirstUpdate = false;
                            iterateUpdateStep();
                        });
                };

                const iterateUpdateStep = function() {
                    window.setTimeout(() => { update(); }, animationStepDelay);
                };

                update();
            })();

            // Iframe

            (function() {

                const $here = {};
                $here.body = document.body;
                $here.iframeContainer = document.getElementById("inner-frame-container")
                $here.iframe = $here.iframeContainer.getElementsByTagName("iframe")[0];

                Array.prototype.forEach.call(document.getElementsByTagName("a"), function(a) {
                    if (!a.target || a.target !== "innerframe") return;
                    a.addEventListener("click", function(e) {
                        $here.body.classList.add("is-loading");
                    });
                });

                $here.iframeContainer.addEventListener("click", function(e) {
                    $here.iframe.src = "?nothing";
                });

                $here.iframe.addEventListener("load", function(e) {
                    const $dest = { win: this.contentWindow };

                    $here.body.classList.remove("is-loading");

                    if (/\?nothing$/.test($dest.win.location.href)) {
                        $here.iframeContainer.classList.remove("shown");
                        return;
                    }

                    $dest.body = $dest.win.document.body;
                    $dest.body.style.background = "#333";
                    $dest.body.style.color = "#eee";
                    $dest.body.style.margin = "30px";

                    if ($dest.body.innerHTML.trim() === "") {
                        $dest.body.innerHTML = "<pre style='opacity:.5;'>(no response body)</pre>";
                    }

                    $here.iframeContainer.classList.add("shown");
                });

            })();

        </script>

    <?php endif; ?>

  </body>

</html>
        <?php
    }

}

GTD::setup();
