/**
 * Cryptonote Node.JS Pool
 * https://github.com/dvandal/cryptonote-nodejs-pool
 *
 * Pool TCP daemon
 **/

// Load required modules
var fs = require('fs');
var net = require('net');
var tls = require('tls');
var async = require('async');
var bignum = require('bignum');

var apiInterfaces = require('./apiInterfaces.js')(config.daemon, config.wallet, config.api);
var notifications = require('./notifications.js');
var utils = require('./utils.js');

var cuHashing = require('cuckaroo29s-hashing');

// Set nonce pattern - must exactly be 8 hex chars
var noncePattern = new RegExp("^[0-9A-Fa-f]{8}$");

// Set redis database cleanup interval
var cleanupInterval = config.redis.cleanupInterval && config.redis.cleanupInterval > 0 ? config.redis.cleanupInterval : 15;

// Initialize log system
var logSystem = 'pool';
require('./exceptionWriter.js')(logSystem);

var threadId = '(Thread ' + process.env.forkId + ') ';
var log = function(severity, system, text, data){
    global.log(severity, system, threadId + text, data);
};

// Set Cuckaroo29 algorithm
var cnAlgorithm = config.cnAlgorithm || "cuckaroo29s";
var cnVariant = config.cnVariant || 0;
var cnBlobType = config.cnBlobType || 7;

var currentBlockHash = "";
var currentBlockHeight = 0;

// Set instance id
var instanceId = utils.instanceId();

// Pool variables
var poolStarted = false;
var connectedMiners = {};

// Pool settings
var shareTrustEnabled = config.poolServer.shareTrust && config.poolServer.shareTrust.enabled;
var shareTrustStepFloat = shareTrustEnabled ? config.poolServer.shareTrust.stepDown / 100 : 0;
var shareTrustMinFloat = shareTrustEnabled ? config.poolServer.shareTrust.min / 100 : 0;

var banningEnabled = config.poolServer.banning && config.poolServer.banning.enabled;
var bannedIPs = {};
var perIPStats = {};

var slushMiningEnabled = config.poolServer.slushMining && config.poolServer.slushMining.enabled;

if (!config.poolServer.paymentId) config.poolServer.paymentId = {};
if (!config.poolServer.paymentId.addressSeparator) config.poolServer.paymentId.addressSeparator = "+";

// Set block notification port
if (config.blockNotifier.port)
{
    var ctrl_server = net.createServer(function (localsocket) {
        jobRefresh('ctrlport');
    });
    ctrl_server.listen(config.blockNotifier.port,'127.0.0.1');
}

// Block templates
var validBlockTemplates = [];
var currentBlockTemplate;

// Difficulty buffer
var diff1 = bignum('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16);

/**
 * Convert buffer to byte array
 **/
Buffer.prototype.toByteArray = function () {
    return Array.prototype.slice.call(this, 0);
};
 net.Socket.prototype.minerId = 'dummy';

/**
 * Periodical updaters
 **/

// Variable difficulty retarget
setInterval(function(){
    var now = Date.now() / 1000 | 0;
    for (var minerId in connectedMiners){
        var miner = connectedMiners[minerId];
        if(!miner.noRetarget) {
            miner.retarget(now);
        }
    }
}, config.poolServer.varDiff.retargetTime * 1000);

// Every 30 seconds clear out timed-out miners and old bans
setInterval(function(){
    var now = Date.now();
    var timeout = config.poolServer.minerTimeout * 1000;
    for (var minerId in connectedMiners){
        var miner = connectedMiners[minerId];
        if (now - miner.lastBeat > timeout){
            log('warn', logSystem, 'Miner timed out and disconnected %s@%s', [miner.login, miner.ip]);
            delete connectedMiners[minerId];
            removeConnectedWorker(miner, 'timeout');
        }
    }

    if (banningEnabled){
        for (ip in bannedIPs){
            var banTime = bannedIPs[ip];
            if (now - banTime > config.poolServer.banning.time * 1000) {
                delete bannedIPs[ip];
                delete perIPStats[ip];
                log('info', logSystem, 'Ban dropped for %s', [ip]);
            }
        }
    }

}, 30000);

/**
 * Handle multi-thread messages
 **/
process.on('message', function(message) {
    switch (message.type) {
        case 'banIP':
            bannedIPs[message.ip] = Date.now();
            break;
    }
});

/**
 * Block template
 **/
function BlockTemplate(template){
    this.blob = template.blocktemplate_blob;
    this.difficulty = template.difficulty;
    this.height = template.height;
    this.reserveOffset = template.reserved_offset;
    this.buffer = new Buffer(this.blob, 'hex');
    instanceId.copy(this.buffer, this.reserveOffset + 4, 0, 3);
    this.extraNonce = 0;

    this.previous_hash = new Buffer(32);
    this.buffer.copy(this.previous_hash,0,7,39);
}
BlockTemplate.prototype = {
    nextBlob: function(){
        this.buffer.writeUInt32BE(++this.extraNonce, this.reserveOffset);
        return utils.cnUtil.convert_blob(this.buffer, cnBlobType).toString('hex');
    }
};

/**
 * Get block template
 **/
function getBlockTemplate(callback){
    apiInterfaces.rpcDaemon('getblocktemplate', {reserve_size: 8, wallet_address: config.poolServer.poolAddress}, callback);
}

/**
 * Process block template
 **/
function processBlockTemplate(template){
    if (currentBlockTemplate)
        validBlockTemplates.push(currentBlockTemplate);

    if (validBlockTemplates.length > 3)
        validBlockTemplates.shift();

    currentBlockTemplate = new BlockTemplate(template);

    for (var minerId in connectedMiners){
        var miner = connectedMiners[minerId];
        miner.pushMessage('getjobtemplate', miner.getJob(), minerId);
        miner.pushMessage('message', {'message':'new block at height: '+currentBlockTemplate.height}, minerId);
    }
}

/**
 * Job refresh
 **/
function getBlockCount(callback){
    apiInterfaces.rpcDaemon('getblockcount', {}, callback);
}

function getBlockHash(callback){
    apiInterfaces.rpcDaemon('on_getblockhash', [currentBlockHeight - 1], callback);
}

function jobLoop()
{
    jobRefresh();
    setTimeout(function(){ jobLoop(); }, config.poolServer.blockRefreshInterval);
}

var jobRefreshCompleteCallback = null;
function jobRefreshError(text, error)
{
    log('error', logSystem, text, [error]);
    if(jobRefreshCompleteCallback != null)
        jobRefreshCompleteCallback(false);
}

var jobRefreshCounter = 0;

function jobRefresh(state){
    state = state || "check_force";

    switch(state){
    case "check_force":
        if(jobRefreshCounter % config.poolServer.blockRefreshForce == 0)
            jobRefresh("get_template");
        else
            jobRefresh("check_count");
        jobRefreshCounter++;
        break;

    case "check_count":
        getBlockCount(function(error, result){
            if (error){
                jobRefreshError('Error polling getblockcount %j', error);
                return;
            }

            if(result.count == currentBlockHeight) {
                jobRefresh("check_hash");
                return;
            }

            log('info', logSystem, 'Blockchain height changed to %d, updating template.', [currentBlockHeight]);
            jobRefresh("get_template");
            return;
        });
    break;

    case "ctrlport":
        log('info', logSystem, 'New block notification received from daemon');
    case "check_hash":
        getBlockHash(function(error, result){
            if(error) {
                jobRefreshError('Error polling on_getblockhash %j', error);
                return;
            }

            if(result == currentBlockHash) {
                if(jobRefreshCompleteCallback != null)
                     jobRefreshCompleteCallback(true);
                return;
            }

            log('info', logSystem, 'Blockchain hash changed to %s, updating template.', [currentBlockHash]);
            jobRefresh("get_template");
            return;
        });
    break;

    case "get_template":
        getBlockTemplate(function(error, result){
            if(error) {
                jobRefreshError('Error polling getblocktemplate %j', error);
                return;
            }

            currentBlockHeight = result.height;
            currentBlockHash = result.prev_hash;

            var buffer = new Buffer(result.blocktemplate_blob, 'hex');
            var previous_hash = new Buffer(32);
            buffer.copy(previous_hash,0,7,39);
            if (!currentBlockTemplate || previous_hash.toString('hex') != currentBlockTemplate.previous_hash.toString('hex')){
                for (var minerId in connectedMiners){
                    var miner = connectedMiners[minerId];
                    miner.validJobs = [];
                }
                log('info', logSystem, 'New block to mine at height %d w/ difficulty of %d', [result.height, result.difficulty]);
                processBlockTemplate(result);
            }

            if(jobRefreshCompleteCallback != null)
                jobRefreshCompleteCallback(true);
        });
    }
}
/**
 * Variable difficulty
 **/
var VarDiff = (function(){
    var variance = config.poolServer.varDiff.variancePercent / 100 * config.poolServer.varDiff.targetTime;
    return {
        variance: variance,
        bufferSize: config.poolServer.varDiff.retargetTime / config.poolServer.varDiff.targetTime * 4,
        tMin: config.poolServer.varDiff.targetTime - variance,
        tMax: config.poolServer.varDiff.targetTime + variance,
        maxJump: config.poolServer.varDiff.maxJump
    };
})();

/**
 * Miner
 **/
function Miner(id, login, pass, ip, port, agent, workerName, startingDiff, noRetarget, pushMessage){
    this.id = id;
    this.login = login;
    this.pass = pass;
    this.ip = ip;
    this.port = port;
    this.workerName = workerName;
    this.pushMessage = pushMessage;
    this.heartbeat();
    this.noRetarget = noRetarget;
    this.difficulty = startingDiff;
    this.validJobs = [];

    // Vardiff related variables
    this.shareTimeRing = utils.ringBuffer(16);
    this.lastShareTime = Date.now() / 1000 | 0;

    if (shareTrustEnabled) {
        this.trust = {
            threshold: config.poolServer.shareTrust.threshold,
            probability: 1,
            penalty: 0
        };
    }
}
Miner.prototype = {
    retarget: function(now){

        var options = config.poolServer.varDiff;

        var sinceLast = now - this.lastShareTime;
        var decreaser = sinceLast > VarDiff.tMax;

        var avg = this.shareTimeRing.avg(decreaser ? sinceLast : null);
        var newDiff;

        var direction;

        if (avg > VarDiff.tMax && this.difficulty > options.minDiff){
            newDiff = options.targetTime / avg * this.difficulty;
            newDiff = newDiff > options.minDiff ? newDiff : options.minDiff;
            direction = -1;
        }
        else if (avg < VarDiff.tMin && this.difficulty < options.maxDiff){
            newDiff = options.targetTime / avg * this.difficulty;
            newDiff = newDiff < options.maxDiff ? newDiff : options.maxDiff;
            direction = 1;
        }
        else{
            return;
        }

        if (Math.abs(newDiff - this.difficulty) / this.difficulty * 100 > options.maxJump){
            var change = options.maxJump / 100 * this.difficulty * direction;
            newDiff = this.difficulty + change;
        }

        this.setNewDiff(newDiff);
        this.shareTimeRing.clear();
        if (decreaser) this.lastShareTime = now;
    },
    setNewDiff: function(newDiff){
        newDiff = Math.round(newDiff);
        if (this.difficulty === newDiff) return;
        log('info', logSystem, 'Retargetting difficulty %d to %d for %s', [this.difficulty, newDiff, this.login]);
        this.pendingDifficulty = newDiff;
        this.pushMessage('getjobtemplate', this.getJob(),this.id);
        this.pushMessage('message', {'message':'retarget diff to: '+newDiff},this.id);
    },
    heartbeat: function(){
        this.lastBeat = Date.now();
    },
    getTargetHex: function(){
        if (this.pendingDifficulty){
            this.lastDifficulty = this.difficulty;
            this.difficulty = this.pendingDifficulty;
            this.pendingDifficulty = null;
        }

        var padded = new Buffer(32);
        padded.fill(0);

        var diffBuff = diff1.div(this.difficulty).toBuffer();
        diffBuff.copy(padded, 32 - diffBuff.length);

        var buff = padded.slice(0, 4);
        var buffArray = buff.toByteArray().reverse();
        var buffReversed = new Buffer(buffArray);
        this.target = buffReversed.readUInt32BE(0);
        var hex = buffReversed.toString('hex');
        return hex;
    },
    getTargetDiff: function(){
        if (this.pendingDifficulty){
            this.lastDifficulty = this.difficulty;
            this.difficulty = this.pendingDifficulty;
            this.pendingDifficulty = null;
        }

        return this.difficulty;
    },
    getJob: function(){
        if (this.lastBlockHeight === currentBlockTemplate.height && !this.pendingDifficulty && this.cachedJob !== null) {
            return this.cachedJob;
        }

        var blob = currentBlockTemplate.nextBlob();
        this.lastBlockHeight = currentBlockTemplate.height;
        var difftarget = this.getTargetDiff();

        var newJob = {
            id: utils.uid(),
            extraNonce: currentBlockTemplate.extraNonce,
            height: currentBlockTemplate.height,
            difficulty: this.difficulty,
            diffHex: this.diffHex,
            submissions: []
        };

        this.validJobs.push(newJob);

        if (this.validJobs.length > 4)
            this.validJobs.shift();

        this.cachedJob = {
            pre_pow: blob,
            height: newJob.height,
            algo: "cuckaroo",
            edgebits: 29,
            proofsize: 32,
            noncebytes: 4,
            job_id: newJob.id,
            difficulty: difftarget,
            id: this.id
        };
        return this.cachedJob;
    },
    checkBan: function(validShare){
        if (!banningEnabled) return;

        // Init global per-ip shares stats
        if (!perIPStats[this.ip]){
            perIPStats[this.ip] = { validShares: 0, invalidShares: 0 };
        }

        var stats = perIPStats[this.ip];
        validShare ? stats.validShares++ : stats.invalidShares++;

        if (stats.validShares + stats.invalidShares >= config.poolServer.banning.checkThreshold){
            if (stats.invalidShares / stats.validShares >= config.poolServer.banning.invalidPercent / 100){
                validShare ? this.validShares++ : this.invalidShares++;
                log('warn', logSystem, 'Banned %s@%s', [this.login, this.ip]);
                bannedIPs[this.ip] = Date.now();
                delete connectedMiners[this.id];
                process.send({type: 'banIP', ip: this.ip});
                removeConnectedWorker(this, 'banned');
            }
            else{
                stats.invalidShares = 0;
                stats.validShares = 0;
            }
        }
    }
};

/**
 * Handle miner method
 **/
function handleMinerMethod(method, params, ip, portData, sendReply, pushMessage, setMinerid){
    var miner = connectedMiners[params.id];

    // Check for ban here, so preconnected attackers can't continue to screw you
    if (IsBannedIp(ip)){
        sendReply('Your IP is banned');
        return;
    }

    switch(method){
        case 'login':
            var login = params.login;
            if (!login){
                if (params.agent && params.agent.includes('Swap')) {
                    sendReply({code: -32600, message: "Missing login"}, null, 'submit');
                }
                else{
                    sendReply('Missing login');
                }
                return;
            }

            var port = portData.port;

            var pass = params.pass;
            var workerName = '';
            if (params.rigid) {
                workerName = params.rigid.trim();
            }
            else if (pass) {
                workerName = pass.trim();
                if (pass.indexOf(':') >= 0 && pass.indexOf('@') >= 0) {
                    passDelimiterPos = pass.lastIndexOf(':');
                    workerName = pass.substr(0, passDelimiterPos).trim();
                }
                workerName = workerName.replace(/:/g, '');
                workerName = workerName.replace(/\+/g, '');
                workerName = workerName.replace(/\s/g, '');
            }
            if (!workerName || workerName === '') {
                workerName = 'undefined';
            }
            workerName = utils.cleanupSpecialChars(workerName);
        
            var difficulty = portData.difficulty;
            var noRetarget = false;
            if(config.poolServer.fixedDiff.enabled) {
                var fixedDiffCharPos = login.lastIndexOf(config.poolServer.fixedDiff.addressSeparator);
                if (fixedDiffCharPos !== -1 && (login.length - fixedDiffCharPos < 32)){
                    diffValue = login.substr(fixedDiffCharPos + 1);
                    difficulty = parseInt(diffValue);
                    login = login.substr(0, fixedDiffCharPos);
                    if (!difficulty || difficulty != diffValue) {
                        log('warn', logSystem, 'Invalid difficulty value "%s" for login: %s', [diffValue, login]);
                        difficulty = portData.difficulty;
                    } else {
                        noRetarget = true;
                        if (difficulty < config.poolServer.varDiff.minDiff) {
                            difficulty = config.poolServer.varDiff.minDiff;
                        }
                    }
                }
            }

            var addr = login.split(config.poolServer.paymentId.addressSeparator);
            var address = addr[0] || null;

            if (!address) {
                log('warn', logSystem, 'No address specified for login');
                sendReply({code: -32600, message: "Invalid address used for login"}, null, 'submit');
            }

            if (!utils.validateMinerAddress(address)) {
                var addressPrefix = utils.getAddressPrefix(address);
                if (!addressPrefix) {addressPrefix = 'N/A';}

                log('warn', logSystem, 'Invalid address used for login (prefix: %s): %s', [addressPrefix, address]);
                sendReply({code: -32600, message: "Invalid address used for login"}, null, 'submit');
                return;
            }

            var minerId = utils.uid();
            miner = new Miner(minerId, login, pass, ip, port, params.agent, workerName, difficulty, noRetarget, pushMessage);
            connectedMiners[minerId] = miner;
            setMinerid(minerId);
            
            miner.pushMessage('login', 'ok',minerId);
            var job = miner.getJob();
            sendReply(null, {
                id: minerId,
                pre_pow:job.pre_pow,
                height: job.height,
                algo: "cuckaroo",
                edgebits: 29,
                proofsize: 32,
                noncebytes: 4,
                height: job.height,
                job_id:job.job_id,
                difficulty: job.difficulty,
                status: 'OK'
            },'getjobtemplate');

            newConnectedWorker(miner);
            break;
        case 'submit':
            if (!miner){
                sendReply({code: -32504, message: "Unauthenticated"}, null, 'submit');
                return;
            }
            miner.heartbeat();

            var job = miner.validJobs.filter(function(job){
                return job.id === params.job_id.toString();
            })[0];

            job = miner.validJobs[miner.validJobs.length-1];

            if (!job){
                sendReply(null,"stale", 'submit');
                return;
            }


            if (!params.nonce) {
                sendReply('Attack detected');
                var minerText = miner ? (' ' + miner.login + '@' + miner.ip) : '';
                log('warn', logSystem, 'Malformed miner share: ' + JSON.stringify(params) + ' from ' + minerText);
                return;
            }

            // Force lowercase for further comparison
            params.nonce = params.nonce.toString().toLowerCase();

            var cycle = params.pow.join(':');
            if (job.submissions.indexOf(cycle) !== -1){
                var minerText = miner ? (' ' + miner.login + '@' + miner.ip) : '';
                log('warn', logSystem, 'Duplicate share: ' + JSON.stringify(params) + ' from ' + minerText);
                perIPStats[miner.ip] = { validShares: 0, invalidShares: 999999 };
                miner.checkBan(false);
                sendReply({code: -32505, message: "Duplicate share"}, null, 'submit');
                return;
            }

            job.submissions.push(cycle);

            var blockTemplate = currentBlockTemplate.height === job.height ? currentBlockTemplate : validBlockTemplates.filter(function(t){
                return t.height === job.height;
            })[0];

            if (!blockTemplate){
                sendReply({code: -32600, message: "Block expired"}, null, 'submit');
                return;
            }

            var shareAccepted = processShare(miner, job, blockTemplate, params);
            miner.checkBan(shareAccepted);
            
            if (shareTrustEnabled){
                if (shareAccepted){
                    miner.trust.probability -= shareTrustStepFloat;
                    if (miner.trust.probability < shareTrustMinFloat)
                        miner.trust.probability = shareTrustMinFloat;
                    miner.trust.penalty--;
                    miner.trust.threshold--;
                }
                else{
                    log('warn', logSystem, 'Share trust broken by %s@%s', [miner.login, miner.ip]);
                    miner.trust.probability = 1;
                    miner.trust.penalty = config.poolServer.shareTrust.penalty;
                }
            }
            
            if (!shareAccepted){
                sendReply({code: -32502, message: "wrong hash"}, null, 'submit');
                return;
            }

            var now = Date.now() / 1000 | 0;
            miner.shareTimeRing.append(now - miner.lastShareTime);
            miner.lastShareTime = now;
            //miner.retarget(now);

            sendReply(null, 'ok', 'submit');
            break;
        case 'keepalived' :
            if (!miner){
                sendReply('Unauthenticated');
                return;
            }
            miner.heartbeat();
            sendReply(null, { status:'KEEPALIVED' });
            break;
        default:
            sendReply('Invalid method');
            var minerText = miner ? (' ' + miner.login + '@' + miner.ip) : '';
            log('warn', logSystem, 'Invalid method: %s (%j) from %s', [method, params, minerText]);
            break;
    }
}

/**
 * New connected worker
 **/
function newConnectedWorker(miner){
    log('info', logSystem, 'Miner connected %s@%s on port', [miner.login, miner.ip, miner.port]);
    if (miner.workerName !== 'undefined') log('info', logSystem, 'Worker Name: %s', [miner.workerName]);
    if (miner.difficulty) log('info', logSystem, 'Miner difficulty fixed to %s', [miner.difficulty]);

    redisClient.sadd(config.coin + ':workers_ip:' + miner.login, miner.ip);
    redisClient.hincrby(config.coin + ':ports:'+miner.port, 'users', 1);

    redisClient.hincrby(config.coin + ':active_connections', miner.login + '~' + miner.workerName, 1, function(error, connectedWorkers) {
        if (connectedWorkers === 1) {
            notifications.sendToMiner(miner.login, 'workerConnected', {
                'LOGIN' : miner.login,
                'MINER': miner.login.substring(0,7)+'...'+miner.login.substring(miner.login.length-7),
                'IP': miner.ip.replace('::ffff:', ''),
                'PORT': miner.port,
                'WORKER_NAME': miner.workerName !== 'undefined' ? miner.workerName : ''
            });
        }
    });
}

/**
 * Remove connected worker
 **/
function removeConnectedWorker(miner, reason){
    redisClient.hincrby(config.coin + ':ports:'+miner.port, 'users', '-1');

    redisClient.hincrby(config.coin + ':active_connections', miner.login + '~' + miner.workerName, -1, function(error, connectedWorkers) {
        if (reason === 'banned') {
            notifications.sendToMiner(miner.login, 'workerBanned', {
                'LOGIN' : miner.login,
                'MINER': miner.login.substring(0,7)+'...'+miner.login.substring(miner.login.length-7),
                'IP': miner.ip.replace('::ffff:', ''),
                'PORT': miner.port,
                'WORKER_NAME': miner.workerName !== 'undefined' ? miner.workerName : ''
            });
        } else if (!connectedWorkers || connectedWorkers <= 0) {
            notifications.sendToMiner(miner.login, 'workerTimeout', {
                'LOGIN' : miner.login,
                'MINER': miner.login.substring(0,7)+'...'+miner.login.substring(miner.login.length-7),
                'IP': miner.ip.replace('::ffff:', ''),
                'PORT': miner.port,
                'WORKER_NAME': miner.workerName !== 'undefined' ? miner.workerName : '',
                'LAST_HASH': utils.dateFormat(new Date(miner.lastBeat), 'yyyy-mm-dd HH:MM:ss Z')
            });
       }
    });
}

/**
 * Return if IP has been banned
 **/
function IsBannedIp(ip){
    if (!banningEnabled || !bannedIPs[ip]) return false;

    var bannedTime = bannedIPs[ip];
    var bannedTimeAgo = Date.now() - bannedTime;
    var timeLeft = config.poolServer.banning.time * 1000 - bannedTimeAgo;
    if (timeLeft > 0){
        return true;
    }
    else {
        delete bannedIPs[ip];
        log('info', logSystem, 'Ban dropped for %s', [ip]);
        return false;
    }
}

/**
 * Record miner share data
 **/
function recordShareData(miner, job, shareDiff, blockCandidate, hashHex, shareType, blockTemplate){
    var dateNow = Date.now();
    var dateNowSeconds = dateNow / 1000 | 0;

    var updateScore;
    // Weighting older shares lower than newer ones to prevent pool hopping
    if (slushMiningEnabled) {
        // We need to do this via an eval script because we need fetching the last block time and
        // calculating the score to run in a single transaction (otherwise we could have a race
        // condition where a block gets discovered between the time we look up lastBlockFound and
        // insert the score, which would give the miner an erroneously huge proportion on the new block)
        updateScore = ['eval', `
            local age = (ARGV[3] - redis.call('hget', KEYS[2], 'lastBlockFound')) / 1000
            local score = string.format('%.17g', ARGV[2] * math.exp(age / ARGV[4]))
            redis.call('hincrbyfloat', KEYS[1], ARGV[1], score)
            return {score, tostring(age)}
            `,
            2 /*keys*/, config.coin + ':scores:roundCurrent', config.coin + ':stats',
            /* args */ miner.login, job.difficulty, Date.now(), config.poolServer.slushMining.weight];
    }
    else {
        job.score = job.difficulty;
        updateScore = ['hincrbyfloat', config.coin + ':scores:roundCurrent', miner.login, job.score]
    }

    var redisCommands = [
        updateScore,
        ['hincrby', config.coin + ':shares_actual:roundCurrent', miner.login, job.difficulty],
        ['zadd', config.coin + ':hashrate', dateNowSeconds, [job.difficulty*32, miner.login, dateNow].join(':')],
        ['hincrby', config.coin + ':workers:' + miner.login, 'hashes', job.difficulty*32],
        ['hset', config.coin + ':workers:' + miner.login, 'lastShare', dateNowSeconds],
        ['expire', config.coin + ':workers:' + miner.login, (86400 * cleanupInterval)],
        ['expire', config.coin + ':payments:' + miner.login, (86400 * cleanupInterval)]
    ];

    if (miner.workerName) {
        redisCommands.push(['zadd', config.coin + ':hashrate', dateNowSeconds, [job.difficulty*32, miner.login + '~' + miner.workerName, dateNow].join(':')]);
        redisCommands.push(['hincrby', config.coin + ':unique_workers:' + miner.login + '~' + miner.workerName, 'hashes', job.difficulty*32]);
        redisCommands.push(['hset', config.coin + ':unique_workers:' + miner.login + '~' + miner.workerName, 'lastShare', dateNowSeconds]);
        redisCommands.push(['expire', config.coin + ':unique_workers:' + miner.login + '~' + miner.workerName, (86400 * cleanupInterval)]);
    }
    
    if (blockCandidate){
        redisCommands.push(['hset', config.coin + ':stats', 'lastBlockFound', Date.now()]);
        redisCommands.push(['rename', config.coin + ':scores:roundCurrent', config.coin + ':scores:round' + job.height]);
        redisCommands.push(['rename', config.coin + ':shares_actual:roundCurrent', config.coin + ':shares_actual:round' + job.height]);
        redisCommands.push(['hgetall', config.coin + ':scores:round' + job.height]);
        redisCommands.push(['hgetall', config.coin + ':shares_actual:round' + job.height]);
    }

    redisClient.multi(redisCommands).exec(function(err, replies){
        if (err){
            log('error', logSystem, 'Failed to insert share data into redis %j \n %j', [err, redisCommands]);
            return;
        }

        if (slushMiningEnabled) {
            job.score = parseFloat(replies[0][0]);
            var age = parseFloat(replies[0][1]);
            log('info', logSystem, 'Submitted score ' + job.score + ' for difficulty ' + job.difficulty + ' and round age ' + age + 's');
        }

        if (blockCandidate){
            var workerScores = replies[replies.length - 2];
            var workerShares = replies[replies.length - 1];
            var totalScore = Object.keys(workerScores).reduce(function(p, c){
                return p + parseFloat(workerScores[c])
            }, 0);
            var totalShares = Object.keys(workerShares).reduce(function(p, c){
                return p + parseInt(workerShares[c])
            }, 0);
            redisClient.zadd(config.coin + ':blocks:candidates', job.height, [
                hashHex,
                Date.now() / 1000 | 0,
                blockTemplate.difficulty,
                totalShares,
                totalScore
            ].join(':'), function(err, result){
                if (err){
                    log('error', logSystem, 'Failed inserting block candidate %s \n %j', [hashHex, err]);
                }
            });

            notifications.sendToAll('blockFound', {
                'HEIGHT': job.height,
                'HASH': hashHex,
                'DIFFICULTY': blockTemplate.difficulty,
                'SHARES': totalShares,
                'MINER': miner.login.substring(0,7)+'...'+miner.login.substring(miner.login.length-7)
            });
        }

    });

    log('info', logSystem, 'Accepted %s share at difficulty %d/%d from %s@%s', [shareType, job.difficulty, shareDiff, miner.login, miner.ip]);
}

/**
 * Process miner share data
 **/
function processShare(miner, job, blockTemplate, params){
    var nonce = params.nonce;
    var resultHash = params.result;
    var template = new Buffer(blockTemplate.buffer.length);
    blockTemplate.buffer.copy(template);
    template.writeUInt32BE(job.extraNonce, blockTemplate.reserveOffset);
    var shareBuffer;
    
    var shareType;
    var hashDiff=0;
    var jobdiff = cuHashing.getdifficultyfromhash(cuHashing.cycle_hash(params.pow));

    shareBuffer = utils.cnUtil.construct_block_blob(template, bignum(nonce,10).toBuffer({endian : 'little',size : 4}),cnBlobType,params.pow);
    
    var header =  Buffer.concat([utils.cnUtil.convert_blob(shareBuffer,cnBlobType),bignum(nonce,10).toBuffer({endian : 'big',size : 4})]);
    prooferror = cuHashing.cuckaroo29s(header,params.pow);
        
    if(prooferror){

        log('warn', logSystem, 'Bad hash from miner %s@%s', [miner.login, miner.ip]);
        return false;
    }
    else{
        hash=cuHashing.cycle_hash(params.pow);
        shareType = 'valid';
        hashDiff = bignum(jobdiff);
    }

    if (hashDiff.ge(blockTemplate.difficulty)){

        apiInterfaces.rpcDaemon('submitblock', [shareBuffer.toString('hex')], function(error, result){
            if (error){
                log('error', logSystem, 'Error submitting block at height %d from %s@%s, share type: "%s" - %j', [job.height, miner.login, miner.ip, shareType, error]);
                recordShareData(miner, job, hashDiff.toString(), false, null, shareType);
            }
            else{
                var blockFastHash = utils.cnUtil.get_block_id(shareBuffer, cnBlobType).toString('hex');
                log('info', logSystem,
                    'Block %s found at height %d by miner %s@%s - submit result: %j',
                    [blockFastHash.substr(0, 6), job.height, miner.login, miner.ip, result]
                );
                recordShareData(miner, job, hashDiff.toString(), true, blockFastHash, shareType, blockTemplate);
                jobRefresh();
            }
        });
    }

    else if (hashDiff.lt(job.difficulty)){
        log('warn', logSystem, 'Rejected low difficulty share of %s from %s@%s', [hashDiff.toString(), miner.login, miner.ip]);
        return false;
    }
    else{
        recordShareData(miner, job, hashDiff.toString(), false, null, shareType);
    }

    return true;
}

/**
 * Start pool server on TCP ports
 **/
var httpResponse = ' 200 OK\nContent-Type: text/plain\nContent-Length: 20\n\nMining server online';

function startPoolServerTcp(callback){
    log('info', logSystem, 'Clear values for connected workers in redis database.');
    redisClient.del(config.coin + ':active_connections');

    async.each(config.poolServer.ports, function(portData, cback){
        var handleMessage = function(socket, jsonData, pushMessage){

            if (!jsonData.id) {
                log('warn', logSystem, 'Miner RPC request missing RPC id');
                return;
            }
            else if (!jsonData.method) {
                log('warn', logSystem, 'Miner RPC request missing RPC method');
                return;
            }

            var sendReply = function(error, result, method){
                if(!socket.writable) return;
                var sendData = JSON.stringify({
                    id: jsonData.id,
                    jsonrpc: "2.0",
                    error: error ? {code: -1, message: error} : null,
                    result: result
                }) + "\n";
                if(method) sendData = JSON.stringify({
                    id: jsonData.id,
                    jsonrpc: "2.0",
                    method: method,
                    error: error,
                    result: result
                }) + "\n";
                socket.write(sendData);
            };
            var setMinerid = function(minerid){
                socket.minerId=minerid;
            };              
            if(socket.minerId !== 'dummy') {
                if(jsonData.params) jsonData.params.id=socket.minerId;
            }

            if( jsonData.result ) {
                handleMinerMethod(jsonData.method, jsonData.result, socket.remoteAddress, portData, sendReply, pushMessage, setMinerid);
            }
            else{
                if(!jsonData.params && jsonData.method && jsonData.method === "getjobtemplate") return;
                handleMinerMethod(jsonData.method, jsonData.params, socket.remoteAddress, portData, sendReply, pushMessage, setMinerid);
            }
        };

        var socketResponder = function(socket){
            socket.setKeepAlive(true);
            socket.setEncoding('utf8');

            var dataBuffer = '';

            var pushMessage = function(method, params,id){
                if(!socket.writable) return;
                var sendData = JSON.stringify({
                    jsonrpc: "2.o",
                    id: id,
                    method: method,
                    result: params
                }) + "\n";
                socket.write(sendData);
            };

            socket.on('data', function(d){
                dataBuffer += d;
                if (Buffer.byteLength(dataBuffer, 'utf8') > 10240){ //10KB
                    dataBuffer = null;
                    log('warn', logSystem, 'Socket flooding detected and prevented from %s', [socket.remoteAddress]);
                    socket.destroy();
                    return;
                }
                if (dataBuffer.indexOf('\n') !== -1){
                    var messages = dataBuffer.split('\n');
                    var incomplete = dataBuffer.slice(-1) === '\n' ? '' : messages.pop();
                    for (var i = 0; i < messages.length; i++){
                        var message = messages[i];
                        if (message.trim() === '') continue;
                        var jsonData;
                        try{
                            jsonData = JSON.parse(message);
                        }
                        catch(e){
                            if (message.indexOf('GET /') === 0) {
                                if (message.indexOf('HTTP/1.1') !== -1) {
                                    socket.end('HTTP/1.1' + httpResponse);
                                    break;
                                }
                                else if (message.indexOf('HTTP/1.0') !== -1) {
                                    socket.end('HTTP/1.0' + httpResponse);
                                    break;
                                }
                            }

                            log('warn', logSystem, 'Malformed message from %s: %s', [socket.remoteAddress, message]);
                            socket.destroy();

                            break;
                        }
                        try {
                            handleMessage(socket, jsonData, pushMessage);
                        } catch (e) {
                            log('warn', logSystem, 'Malformed message from ' + socket.remoteAddress + ' generated an exception. Message: ' + message);
                            if (e.message) log('warn', logSystem, 'Exception: ' + e.message);
                        }
                     }
                    dataBuffer = incomplete;
                }
            }).on('error', function(err){
                if (err.code !== 'ECONNRESET')
                    log('warn', logSystem, 'Socket error from %s %j', [socket.remoteAddress, err]);
            }).on('close', function(){
                pushMessage = function(){};
            });
        };

        if (portData.ssl) {
            if (!config.poolServer.sslCert) {
                log('error', logSystem, 'Could not start server listening on port %d (SSL): SSL certificate not configured', [portData.port]);
                cback(true);
            } else if (!config.poolServer.sslKey) {
                log('error', logSystem, 'Could not start server listening on port %d (SSL): SSL key not configured', [portData.port]);
                cback(true);
            } else if (!config.poolServer.sslCA) {
                log('error', logSystem, 'Could not start server listening on port %d (SSL): SSL certificate authority not configured', [portData.port]);
                cback(true);
            } else if (!fs.existsSync(config.poolServer.sslCert)) {
                log('error', logSystem, 'Could not start server listening on port %d (SSL): SSL certificate file not found (configuration error)', [portData.port]);
                cback(true);
            } else if (!fs.existsSync(config.poolServer.sslKey)) {
                log('error', logSystem, 'Could not start server listening on port %d (SSL): SSL key file not found (configuration error)', [portData.port]);
                cback(true);
            } else if (!fs.existsSync(config.poolServer.sslCA)) {
                log('error', logSystem, 'Could not start server listening on port %d (SSL): SSL certificate authority file not found (configuration error)', [portData.port]);
                cback(true);
            } else {
                var options = {
                    key: fs.readFileSync(config.poolServer.sslKey),
                    cert: fs.readFileSync(config.poolServer.sslCert),
                    ca: fs.readFileSync(config.poolServer.sslCA)
                };
                tls.createServer(options, socketResponder).listen(portData.port, function (error, result) {
                    if (error) {
                        log('error', logSystem, 'Could not start server listening on port %d (SSL), error: $j', [portData.port, error]);
                        cback(true);
                        return;
                    }

                    log('info', logSystem, 'Clear values for SSL port %d in redis database.', [portData.port]);
                    redisClient.del(config.coin + ':ports:'+portData.port);
                    redisClient.hset(config.coin + ':ports:'+portData.port, 'port', portData.port);

                    log('info', logSystem, 'Started server listening on port %d (SSL)', [portData.port]);
                    cback();
                });
            }
        }
        else {
            net.createServer(socketResponder).listen(portData.port, function (error, result) {
                if (error) {
                    log('error', logSystem, 'Could not start server listening on port %d, error: $j', [portData.port, error]);
                    cback(true);
                    return;
                }

                log('info', logSystem, 'Clear values for port %d in redis database.', [portData.port]);
                redisClient.del(config.coin + ':ports:'+portData.port);
                redisClient.hset(config.coin + ':ports:'+portData.port, 'port', portData.port);

                log('info', logSystem, 'Started server listening on port %d', [portData.port]);
                cback();
            });
        }
    }, function(err){
        if (err)
            callback(false);
        else
            callback(true);
    });
}

/**
 * Initialize pool server
 **/

(function init(){
    jobRefreshCompleteCallback = function(sucessful){
        if (!sucessful){
            log('error', logSystem, 'Could not start pool');
            return;
        }
        startPoolServerTcp(function(successful){ });
        jobRefreshCompleteCallback = null;
    };

    jobLoop();
})();
