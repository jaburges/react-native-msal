package com.reactnativemsal;

import android.app.Activity;
import android.util.Pair;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;
import com.microsoft.identity.client.AuthenticationCallback;
import com.microsoft.identity.client.AcquireTokenParameters;
import com.microsoft.identity.client.AcquireTokenSilentParameters;
import com.microsoft.identity.client.Prompt;
import com.microsoft.identity.client.IAccount;
import com.microsoft.identity.client.IAuthenticationResult;
import com.microsoft.identity.client.IMultipleAccountPublicClientApplication;
import com.microsoft.identity.client.IPublicClientApplication;
import com.microsoft.identity.client.PublicClientApplication;
import com.microsoft.identity.client.exception.MsalException;
import com.microsoft.identity.client.SilentAuthenticationCallback;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class RNMSALModule extends ReactContextBaseJavaModule {
    private static final String E_NO_CURRENT_APPLICATION = "E_NO_CURRENT_APPLICATION";
    private static final String E_NO_ACTIVITY = "E_NO_ACTIVITY";
    private static final String E_FAILED_TO_CREATE_APPLICATION = "E_FAILED_TO_CREATE_APPLICATION";
    private static final String E_FAILED_TO_ACQUIRE_TOKEN = "E_FAILED_TO_ACQUIRE_TOKEN";

    private final ReactApplicationContext reactContext;
    private IMultipleAccountPublicClientApplication publicClientApplication;

    public RNMSALModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    @Override
    public String getName() {
        return "RNMSAL";
    }

    @ReactMethod
    public void createPublicClientApplication(String configFileString, final Promise promise) {
        try {
            File configFile = new File(configFileString);
            PublicClientApplication.createMultipleAccountPublicClientApplication(
                    reactContext,
                    configFile,
                    new IPublicClientApplication.IMultipleAccountApplicationCreatedListener() {
                        @Override
                        public void onCreated(IMultipleAccountPublicClientApplication application) {
                            publicClientApplication = application;
                            promise.resolve(true);
                        }

                        @Override
                        public void onError(MsalException exception) {
                            promise.reject(E_FAILED_TO_CREATE_APPLICATION, exception);
                        }
                    });
        } catch (Exception e) {
            promise.reject(E_FAILED_TO_CREATE_APPLICATION, e);
        }
    }

    @ReactMethod
    public void acquireToken(final ReadableMap parameters, final Promise promise) {
        if (publicClientApplication == null) {
            promise.reject(E_NO_CURRENT_APPLICATION, "No public client application was found");
            return;
        }

        try {
            Activity activity = getCurrentActivity();
            if (activity == null) {
                promise.reject(E_NO_ACTIVITY, "No current activity");
                return;
            }

            String[] scopes = readableArrayToStringArray(parameters.getArray("scopes"));

            AuthenticationCallback callback = new AuthenticationCallback() {
                @Override
                public void onSuccess(IAuthenticationResult authenticationResult) {
                    promise.resolve(msalResultToDictionary(authenticationResult));
                }

                @Override
                public void onError(MsalException exception) {
                    promise.reject(E_FAILED_TO_ACQUIRE_TOKEN, exception);
                }

                @Override
                public void onCancel() {
                    promise.reject("USER_CANCELLED", "User cancelled the flow");
                }
            };

            if (parameters.hasKey("authority")) {
                String authority = parameters.getString("authority");
                publicClientApplication.acquireToken(activity, scopes, authority, callback);
            } else {
                publicClientApplication.acquireToken(activity, scopes, callback);
            }

        } catch (Exception e) {
            promise.reject(E_FAILED_TO_ACQUIRE_TOKEN, e);
        }
    }

    @ReactMethod
    public void acquireTokenSilent(final ReadableMap parameters, final Promise promise) {
        if (publicClientApplication == null) {
            promise.reject(E_NO_CURRENT_APPLICATION, "No public client application was found");
            return;
        }

        try {
            String accountIdentifier = parameters.getString("accountIdentifier");
            IAccount requestAccount = null;

            List<IAccount> accounts = publicClientApplication.getAccounts();
            if (accounts != null) {
                for (IAccount account : accounts) {
                    if (account.getId().equals(accountIdentifier)) {
                        requestAccount = account;
                        break;
                    }
                }
            }

            if (requestAccount == null) {
                promise.reject(E_FAILED_TO_ACQUIRE_TOKEN, "Account not found");
                return;
            }

            String[] scopes = readableArrayToStringArray(parameters.getArray("scopes"));

            SilentAuthenticationCallback callback = new SilentAuthenticationCallback() {
                @Override
                public void onSuccess(IAuthenticationResult authenticationResult) {
                    promise.resolve(msalResultToDictionary(authenticationResult));
                }

                @Override
                public void onError(MsalException exception) {
                    promise.reject(E_FAILED_TO_ACQUIRE_TOKEN, exception);
                }
            };

            if (parameters.hasKey("authority")) {
                String authority = parameters.getString("authority");
                publicClientApplication.acquireTokenSilentAsync(scopes, requestAccount, authority, callback);
            } else {
                String authority = publicClientApplication.getConfiguration().getDefaultAuthority().getAuthorityURL().toString();
                publicClientApplication.acquireTokenSilentAsync(scopes, requestAccount, authority, callback);
            }

        } catch (Exception e) {
            promise.reject(E_FAILED_TO_ACQUIRE_TOKEN, e);
        }
    }

    @ReactMethod
    public void getAccounts(Promise promise) {
        try {
            List<IAccount> accounts = publicClientApplication.getAccounts();
            WritableArray array = Arguments.createArray();
            if (accounts != null) {
                for (IAccount account : accounts) {
                    array.pushMap(accountToMap(account));
                }
            }
            promise.resolve(array);
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    @ReactMethod
    public void getAccount(String accountIdentifier, Promise promise) {
        try {
            IAccount account = publicClientApplication.getAccount(accountIdentifier);
            if (account != null) {
                promise.resolve(accountToMap(account));
            } else {
                promise.resolve(null);
            }
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    @ReactMethod
    public void removeAccount(ReadableMap accountIn, Promise promise) {
        try {
            String accountIdentifier = accountIn.getString("identifier");
            IAccount account = publicClientApplication.getAccount(accountIdentifier);

            if (account != null) {
                publicClientApplication.removeAccount(account, new IMultipleAccountPublicClientApplication.RemoveAccountCallback() {
                    @Override
                    public void onRemoved() {
                        promise.resolve(true);
                    }

                    @Override
                    public void onError(@NonNull MsalException exception) {
                        promise.reject(exception);
                    }
                });
            } else {
                promise.resolve(false);
            }
        } catch (Exception e) {
            promise.reject(e);
        }
    }

    private String[] readableArrayToStringArray(ReadableArray array) {
        String[] stringArray = new String[array.size()];
        for (int i = 0; i < array.size(); i++) {
            stringArray[i] = array.getString(i);
        }
        return stringArray;
    }

    private WritableMap msalResultToDictionary(IAuthenticationResult result) {
        WritableMap resultData = Arguments.createMap();
        resultData.putString("accessToken", result.getAccessToken());
        resultData.putString("idToken", result.getAccount().getId());
        resultData.putString("tenantId", result.getTenantId());
        resultData.putString("scopes", String.join(" ", result.getScope()));
        return resultData;
    }

    private WritableMap accountToMap(@NonNull IAccount account) {
        WritableMap map = Arguments.createMap();
        map.putString("identifier", account.getId());
        map.putString("username", account.getUsername());
        map.putString("tenantId", account.getTenantId());
        Map<String, ?> claims = account.getClaims();
        if (claims != null) {
            map.putMap("claims", toWritableMap(claims));
        }
        return map;
    }

    @NonNull
    private List<String> readableArrayToStringList(@Nullable ReadableArray readableArray) {
        List<String> list = new ArrayList<>();
        if (readableArray != null) {
            for (Object item : readableArray.toArrayList()) {
                list.add(item.toString());
            }
        }
        return list;
    }

    @NonNull
    private WritableMap toWritableMap(@NonNull Map<String, ?> map) {
        WritableMap writableMap = Arguments.createMap();
        for (Map.Entry<String, ?> entry : map.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            if (value == null) {
                writableMap.putNull(key);
            } else if (value instanceof Boolean) {
                writableMap.putBoolean(key, (Boolean) value);
            } else if (value instanceof Double) {
                writableMap.putDouble(key, (Double) value);
            } else if (value instanceof Integer) {
                writableMap.putInt(key, (Integer) value);
            } else if (value instanceof String) {
                writableMap.putString(key, (String) value);
            } else if (value instanceof Map<?, ?>) {
                writableMap.putMap(key, toWritableMap((Map<String, ?>) value));
            } else if (value instanceof List<?>) {
                writableMap.putArray(key, toWritableArray((List<?>) value));
            }
        }
        return writableMap;
    }

    @NonNull
    private WritableArray toWritableArray(@NonNull List<?> list) {
        WritableArray writableArray = Arguments.createArray();
        for (Object value : list.toArray()) {
            if (value == null) {
                writableArray.pushNull();
            } else if (value instanceof Boolean) {
                writableArray.pushBoolean((Boolean) value);
            } else if (value instanceof Double) {
                writableArray.pushDouble((Double) value);
            } else if (value instanceof Integer) {
                writableArray.pushInt((Integer) value);
            } else if (value instanceof String) {
                writableArray.pushString((String) value);
            } else if (value instanceof Map<?, ?>) {
                writableArray.pushMap(toWritableMap((Map<String, ?>) value));
            } else if (value instanceof List<?>) {
                writableArray.pushArray(toWritableArray((List<?>) value));
            }
        }
        return writableArray;
    }
}
