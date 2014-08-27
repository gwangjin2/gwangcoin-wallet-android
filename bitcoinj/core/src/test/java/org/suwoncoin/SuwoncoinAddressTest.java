/**
 * Copyright 2011 Google Inc.
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

package org.suwoncoin;

import com.google.bitcoin.core.*;
import com.google.bitcoin.params.TestNet3Params;
import org.junit.Test;
import org.spongycastle.util.encoders.Hex;

import java.util.Arrays;

import static org.junit.Assert.*;

public class SuwoncoinAddressTest {
    static final NetworkParameters mainParams = SuwoncoinParams.get();

    @Test
    public void stringification() throws Exception {
        Address b = new Address(mainParams, Hex.decode("4a22c3c4cbb31e4d03b15550636762bda0baf85a"));
        assertEquals("sR1PjGKNtDyfVSMTHS5Vk4kv4jBi3tMMbc", b.toString());
    }

    @Test
    public void decoding() throws Exception {
        Address b = new Address(mainParams, "sMMmPYeq5u2YFXw6nSLK5BunCbE2B6zqkZ");
        assertEquals("221ca965650a603b911b930fb9fb4b9b475c40b0", Utils.bytesToHexString(b.getHash160()));
    }

    @Test
    public void errorPaths() {
        // Check the case of a mismatched network.
        try {
            new Address(TestNet3Params.get(), "sR1PjGKNtDyfVSMTHS5Vk4kv4jBi3tMMbc");
            fail();
        } catch (WrongNetworkException e) {
            // Success.
            assertEquals(e.verCode, SuwoncoinParams.get().getAddressHeader());
            assertTrue(Arrays.equals(e.acceptableVersions, TestNet3Params.get().getAcceptableAddressCodes()));
        } catch (AddressFormatException e) {
            fail();
        }
    }

    @Test
    public void getNetwork() throws Exception {
        NetworkParameters params = Address.getParametersFromAddress("sMMmPYeq5u2YFXw6nSLK5BunCbE2B6zqkZ");
        assertEquals(SuwoncoinParams.get().getId(), params.getId());
    }
}
