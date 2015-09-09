/*
 * Copyright 2013 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.gwangcoin;

import com.google.bitcoin.core.Block;
import com.google.bitcoin.core.NetworkParameters;
import com.google.bitcoin.core.Sha256Hash;
import com.google.bitcoin.core.StoredBlock;
import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.core.TransactionInput;
import com.google.bitcoin.core.TransactionOutput;
import com.google.bitcoin.core.Utils;
import com.google.bitcoin.script.Script;
import com.google.bitcoin.script.ScriptOpCodes;
import com.lambdaworks.crypto.SCrypt;

import org.spongycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;

import static com.google.common.base.Preconditions.checkState;

/**
 * Parameters for the testnet, a separate public instance of Bitcoin that has relaxed rules suitable for development
 * and testing of applications and new Bitcoin versions.
 */
public class SuwoncoinParams extends NetworkParameters {
    public SuwoncoinParams() {
        super();
        id = "org.gwangcoin.production";
        proofOfWorkLimit = Utils.decodeCompactBits(0x1e0fffffL);
        addressHeader = 125;    // 48(L) -> 125(s)
        acceptableAddressCodes = new int[] { 125 };
        //port = 9333;
        port = 9777;
        packetMagic = 0xfbc0b6dbL;
        dumpedPrivateKeyHeader = 128 + addressHeader;

        targetTimespan = (int)(12 * 60 * 60);
        interval = targetTimespan/((int)(1 * 60));

        genesisBlock.setDifficultyTarget(0x1e0ffff0L);
        genesisBlock.setTime(1410679571L);
        genesisBlock.setNonce(61134L);
        genesisBlock.removeTransaction(0);
        Transaction t = new Transaction(this);
        try {
            // A script containing the difficulty bits and the following message:
            //
            //   "2014년9월15일, 살림살이 수원시민화폐가 시작됨"
            byte[] bytes = Hex.decode
                    ("04ffff001d01043f32303134eb858439ec9b943135ec9dbc2c2020ec82b4eba6bcec82b4ec9db420ec8898ec9b90ec8b9cebafbced9994ed8f90eab08020ec8b9cec9e91eb90a8");
            t.addInput(new TransactionInput(this, t, bytes));
            ByteArrayOutputStream scriptPubKeyBytes = new ByteArrayOutputStream();
            Script.writeBytes(scriptPubKeyBytes, Hex.decode
                    ("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"));
            scriptPubKeyBytes.write(ScriptOpCodes.OP_CHECKSIG);
            t.addOutput(new TransactionOutput(this, t, Utils.toNanoCoins(1, 0), scriptPubKeyBytes.toByteArray()));
        } catch (Exception e) {
            // Cannot happen.
            throw new RuntimeException(e);
        }
        genesisBlock.addTransaction(t);
        String genesisHash = genesisBlock.getHashAsString();
        checkState(genesisHash.equals("3a6b3fc6cd51b185fab5e904bd609d9a56da1385657cd174a2201271b461f0cf"),
                genesisBlock);
        subsidyDecreaseBlockCount = 1000000;

        dnsSeeds = new String[] {
                "dnsseed-gwangjin.actus.kr",
        };
    }

    private static BigInteger MAX_MONEY = Utils.COIN.multiply(BigInteger.valueOf(10000000000L));
    @Override
    public BigInteger getMaxMoney() { return MAX_MONEY; }

    private static SuwoncoinParams instance;
    public static synchronized SuwoncoinParams get() {
        if (instance == null) {
            instance = new SuwoncoinParams();
        }
        return instance;
    }

    /** The number of previous blocks to look at when calculating the next Block's difficulty */
    @Override
    public int getRetargetBlockCount(StoredBlock cursor) {
        if (cursor.getHeight() + 1 != getInterval()) {
            //Logger.getLogger("wallet_swc").info("Normal GW retarget");
            return getInterval();
        } else {
            //Logger.getLogger("wallet_swc").info("Genesis GW retarget");
            return getInterval() - 1;
        }
    }

    @Override public String getURIScheme() { return "gwangcoin:"; }

    /** Gets the hash of the given block for the purpose of checking its PoW */
    public Sha256Hash calculateBlockPoWHash(Block b) {
        byte[] blockHeader = b.cloneAsHeader().bitcoinSerialize();
        try {
            return new Sha256Hash(Utils.reverseBytes(SCrypt.scrypt(blockHeader, blockHeader, 1024, 1, 1, 32)));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    static {
        NetworkParameters.registerParams(get());
        NetworkParameters.PROTOCOL_VERSION = 70002;
    }
}
