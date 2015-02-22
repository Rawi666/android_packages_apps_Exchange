/* Copyright (C) 2010 The Android Open Source Project.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.exchange.adapter;

import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.content.res.Resources;
import android.os.Environment;
import android.support.v4.content.ContextCompat;

import com.android.emailcommon.provider.Policy;
import com.android.emailcommon.service.PolicyServiceProxy;
import com.android.exchange.Eas;
import com.android.exchange.R;
import com.android.exchange.eas.EasProvision;
import com.android.mail.utils.LogUtils;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;

/**
 * Parse the result of the Provision command
 */
public class ProvisionParser extends Parser {
    private static final String TAG = Eas.LOG_TAG;

    private final Context mContext;
    private Policy mPolicy = null;
    private String mSecuritySyncKey = null;
    private boolean mRemoteWipe = false;
    private boolean mIsSupportable = true;
    private boolean smimeRequired = false;
    private final Resources mResources;

    public ProvisionParser(final Context context, final InputStream in) throws IOException {
        super(in);
        mContext = context;
        mResources = context.getResources();
    }

    public Policy getPolicy() {
        return mPolicy;
    }

    public String getSecuritySyncKey() {
        return mSecuritySyncKey;
    }

    public void setSecuritySyncKey(String securitySyncKey) {
        mSecuritySyncKey = securitySyncKey;
    }

    public boolean getRemoteWipe() {
        return mRemoteWipe;
    }

    public boolean hasSupportablePolicySet() {
        mIsSupportable = true;
        return (mPolicy != null) && mIsSupportable;
    }

    public void clearUnsupportablePolicies() {
        mIsSupportable = true;
        mPolicy.mProtocolPoliciesUnsupported = null;
    }

    private void addPolicyString(StringBuilder sb, int res) {
        sb.append(mResources.getString(res));
        sb.append(Policy.POLICY_STRING_DELIMITER);
    }

    /**
     * Complete setup of a Policy; we normalize it first (removing inconsistencies, etc.) and then
     * generate the tokenized "protocol policies enforced" string.  Note that unsupported policies
     * must have been added prior to calling this method (this is only a possibility with wbxml
     * policy documents, as all versions of the OS support the policies in xml documents).
     */
    private void setPolicy(Policy policy) {
        policy.normalize();
        StringBuilder sb = new StringBuilder();
        if (policy.mDontAllowAttachments) {
            addPolicyString(sb, R.string.policy_dont_allow_attachments);
        }
        if (policy.mRequireManualSyncWhenRoaming) {
            addPolicyString(sb, R.string.policy_require_manual_sync_roaming);
        }
        policy.mProtocolPoliciesEnforced = sb.toString();
        mPolicy = policy;
    }

    private boolean deviceSupportsEncryption() {
        DevicePolicyManager dpm =
                (DevicePolicyManager) mContext.getSystemService(Context.DEVICE_POLICY_SERVICE);
        int status = dpm.getStorageEncryptionStatus();
        return status != DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED;
    }

    private void parseProvisionDocWbxml() throws IOException {
        Policy policy = Policy.NO_POLICY;
        setPolicy(policy);
    }

    /**
     * Return whether or not either of the application list tags specifies any applications
     * @param endTag the tag whose children we're walking through
     * @return whether any applications were specified (by name or by hash)
     * @throws IOException
     */
    private boolean specifiesApplications(int endTag) throws IOException {
        boolean specifiesApplications = false;
        while (nextTag(endTag) != END) {
            switch (tag) {
                case Tags.PROVISION_APPLICATION_NAME:
                case Tags.PROVISION_HASH:
                    specifiesApplications = true;
                    break;
                default:
                    skipTag();
            }
        }
        return specifiesApplications;
    }

    /*package*/ void parseProvisionDocXml(String doc) throws IOException {
        Policy policy = new Policy();

        try {
            XmlPullParserFactory factory = XmlPullParserFactory.newInstance();
            XmlPullParser parser = factory.newPullParser();
            parser.setInput(new ByteArrayInputStream(doc.getBytes()), "UTF-8");
            int type = parser.getEventType();
            if (type == XmlPullParser.START_DOCUMENT) {
                type = parser.next();
                if (type == XmlPullParser.START_TAG) {
                    String tagName = parser.getName();
                    if (tagName.equals("wap-provisioningdoc")) {
                        parseWapProvisioningDoc(parser, policy);
                    }
                }
            }
        } catch (XmlPullParserException e) {
           throw new IOException();
        }

        setPolicy(policy);
    }

    /**
     * Return true if password is required; otherwise false.
     */
    private static boolean parseSecurityPolicy(XmlPullParser parser)
            throws XmlPullParserException, IOException {
        boolean passwordRequired = true;
        while (true) {
            int type = parser.nextTag();
            if (type == XmlPullParser.END_TAG && parser.getName().equals("characteristic")) {
                break;
            } else if (type == XmlPullParser.START_TAG) {
                String tagName = parser.getName();
                if (tagName.equals("parm")) {
                    String name = parser.getAttributeValue(null, "name");
                    if (name.equals("4131")) {
                        String value = parser.getAttributeValue(null, "value");
                        if (value.equals("1")) {
                            passwordRequired = false;
                        }
                    }
                }
            }
        }
        return passwordRequired;
    }

    private static void parseCharacteristic(XmlPullParser parser, Policy policy)
            throws XmlPullParserException, IOException {
        boolean enforceInactivityTimer = true;
        while (true) {
            int type = parser.nextTag();
            if (type == XmlPullParser.END_TAG && parser.getName().equals("characteristic")) {
                break;
            } else if (type == XmlPullParser.START_TAG) {
                if (parser.getName().equals("parm")) {
                    String name = parser.getAttributeValue(null, "name");
                    String value = parser.getAttributeValue(null, "value");
                    if (name.equals("AEFrequencyValue")) {
                        if (enforceInactivityTimer) {
                            if (value.equals("0")) {
                                policy.mMaxScreenLockTime = 1;
                            } else {
                                policy.mMaxScreenLockTime = 60*Integer.parseInt(value);
                            }
                        }
                    } else if (name.equals("AEFrequencyType")) {
                        // "0" here means we don't enforce an inactivity timeout
                        if (value.equals("0")) {
                            enforceInactivityTimer = false;
                        }
                    } else if (name.equals("DeviceWipeThreshold")) {
                        policy.mPasswordMaxFails = Integer.parseInt(value);
                    } else if (name.equals("CodewordFrequency")) {
                        // Ignore; has no meaning for us
                    } else if (name.equals("MinimumPasswordLength")) {
                        policy.mPasswordMinLength = Integer.parseInt(value);
                    } else if (name.equals("PasswordComplexity")) {
                        if (value.equals("0")) {
                            policy.mPasswordMode = Policy.PASSWORD_MODE_STRONG;
                        } else {
                            policy.mPasswordMode = Policy.PASSWORD_MODE_SIMPLE;
                        }
                    }
                }
            }
        }
    }

    private static void parseRegistry(XmlPullParser parser, Policy policy)
            throws XmlPullParserException, IOException {
      while (true) {
          int type = parser.nextTag();
          if (type == XmlPullParser.END_TAG && parser.getName().equals("characteristic")) {
              break;
          } else if (type == XmlPullParser.START_TAG) {
              String name = parser.getName();
              if (name.equals("characteristic")) {
                  parseCharacteristic(parser, policy);
              }
          }
      }
    }

    private static void parseWapProvisioningDoc(XmlPullParser parser, Policy policy)
            throws XmlPullParserException, IOException {
        while (true) {
            int type = parser.nextTag();
            if (type == XmlPullParser.END_TAG && parser.getName().equals("wap-provisioningdoc")) {
                break;
            } else if (type == XmlPullParser.START_TAG) {
                String name = parser.getName();
                if (name.equals("characteristic")) {
                    String atype = parser.getAttributeValue(null, "type");
                    if (atype.equals("SecurityPolicy")) {
                        // If a password isn't required, stop here
                        if (!parseSecurityPolicy(parser)) {
                            return;
                        }
                    } else if (atype.equals("Registry")) {
                        parseRegistry(parser, policy);
                        return;
                    }
                }
            }
        }
    }

    private void parseProvisionData() throws IOException {
        while (nextTag(Tags.PROVISION_DATA) != END) {
            if (tag == Tags.PROVISION_EAS_PROVISION_DOC) {
                parseProvisionDocWbxml();
            } else {
                skipTag();
            }
        }
    }

    private void parsePolicy() throws IOException {
        String policyType = null;
        while (nextTag(Tags.PROVISION_POLICY) != END) {
            switch (tag) {
                case Tags.PROVISION_POLICY_TYPE:
                    policyType = getValue();
                    LogUtils.d(TAG, "Policy type: %s", policyType);
                    break;
                case Tags.PROVISION_POLICY_KEY:
                    mSecuritySyncKey = getValue();
                    break;
                case Tags.PROVISION_STATUS:
                    LogUtils.d(TAG, "Policy status: %s", getValue());
                    break;
                case Tags.PROVISION_DATA:
                    if (policyType.equalsIgnoreCase(EasProvision.EAS_2_POLICY_TYPE)) {
                        // Parse the old style XML document
                        parseProvisionDocXml(getValue());
                    } else {
                        // Parse the newer WBXML data
                        parseProvisionData();
                    }
                    break;
                default:
                    skipTag();
            }
        }
    }

    private void parsePolicies() throws IOException {
        while (nextTag(Tags.PROVISION_POLICIES) != END) {
            if (tag == Tags.PROVISION_POLICY) {
                parsePolicy();
            } else {
                skipTag();
            }
        }
    }

    private void parseDeviceInformation() throws IOException {
        while (nextTag(Tags.SETTINGS_DEVICE_INFORMATION) != END) {
            if (tag == Tags.SETTINGS_STATUS) {
                LogUtils.d(TAG, "DeviceInformation status: %s", getValue());
            } else {
                skipTag();
            }
        }
    }

    @Override
    public boolean parse() throws IOException {
        boolean res = false;
        if (nextTag(START_DOCUMENT) != Tags.PROVISION_PROVISION) {
            throw new IOException();
        }
        while (nextTag(START_DOCUMENT) != END_DOCUMENT) {
            switch (tag) {
                case Tags.PROVISION_STATUS:
                    int status = getValueInt();
                    LogUtils.d(TAG, "Provision status: %d", status);
                    res = (status == 1);
                    break;
                case Tags.SETTINGS_DEVICE_INFORMATION:
                    parseDeviceInformation();
                    break;
                case Tags.PROVISION_POLICIES:
                    parsePolicies();
                    break;
                case Tags.PROVISION_REMOTE_WIPE:
                    // Indicate remote wipe command received
                    mRemoteWipe = true;
                    break;
                default:
                    skipTag();
            }
        }
        return res;
    }

    /**
     * In order to determine whether the device has removable storage, we need to use the
     * StorageVolume class, which is hidden (for now) by the framework.  Without this, we'd have
     * to reject all policies that require sd card encryption.
     *
     * TODO: Rewrite this when an appropriate API is available from the framework
     */
    private boolean hasRemovableStorage() {
        final File[] cacheDirs = ContextCompat.getExternalCacheDirs(mContext);
        return Environment.isExternalStorageRemovable()
                || (cacheDirs != null && cacheDirs.length > 1);
    }
}
