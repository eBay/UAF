package org.ebayopensource.fidouaf.marvin;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.ebayopensource.fidouaf.marvin.client.RegRecord;
import org.ebayopensource.fidouaf.marvin.client.StorageInterface;

/*
 * Copyright 2015 eBay Software Foundation
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

public class Storage implements StorageInterface {
    Gson gson = new GsonBuilder().create();
    String prefix = "storage::";

    @Override
    public void addRecord(RegRecord regRecord) {
        Preferences.setSettingsParam(prefix + regRecord.getKeyId(), gson.toJson(regRecord));
    }

    @Override
    public RegRecord get(String keyId) {
        return gson.fromJson(Preferences.getSettingsParam(prefix + keyId), RegRecord.class);
    }

    @Override
    public void remove(String keyId) {
        Preferences.removeSettingsParam(prefix + keyId);
    }
}
