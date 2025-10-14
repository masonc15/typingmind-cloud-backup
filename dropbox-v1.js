/*
TypingMind Cloud Sync with Dropbox v1 by ITCON, AU
-------------------------
Features:
- Sync typingmind database with Dropbox
- Snapshots on demand
- Automatic daily backups
- Backup management in Extension config UI
- Detailed logging in console
- Memory-efficient data processing
- OAuth 2.0 with PKCE authentication
*/
if (window.typingMindCloudSync) {
  console.log("TypingMind Cloud Sync already loaded");
} else {
  window.typingMindCloudSync = true;

  /**
   * ConfigManager - Manages configuration for Dropbox sync
   * Changes from S3 version:
   * - Replaces AWS credentials (bucketName, region, accessKey, secretKey, endpoint) with Dropbox credentials (appKey, accessToken, refreshToken)
   * - Maintains encryption key (critical for data security)
   * - Updates storage keys from tcs_aws_* to tcs_dropbox_*
   */
  class ConfigManager {
    constructor() {
      this.PEPPER = "tcs-dropbox-v1-pepper-!@#$%^&*()";
      this.config = this.loadConfig();
      this.exclusions = this.loadExclusions();
    }

    _obfuscate(str, key) {
      if (!str || !key) return str;
      const combinedKey = key + this.PEPPER;
      let output = "";
      for (let i = 0; i < str.length; i++) {
        const charCode =
          str.charCodeAt(i) ^ combinedKey.charCodeAt(i % combinedKey.length);
        output += String.fromCharCode(charCode);
      }
      return btoa(output);
    }

    _deobfuscate(b64str, key) {
      if (!b64str || !key) return b64str;
      const combinedKey = key + this.PEPPER;
      let output = "";
      const decodedStr = atob(b64str);
      for (let i = 0; i < decodedStr.length; i++) {
        const charCode =
          decodedStr.charCodeAt(i) ^
          combinedKey.charCodeAt(i % combinedKey.length);
        output += String.fromCharCode(charCode);
      }
      return output;
    }

    loadConfig() {
      const defaults = {
        syncInterval: 15,
        appKey: "",
        accessToken: "",
        refreshToken: "",
        tokenExpiry: 0,
        encryptionKey: "",
      };

      const stored = {};
      const encryptionKey = localStorage.getItem("tcs_encryptionkey") || "";

      Object.keys(defaults).forEach((key) => {
        let storageKey;
        if (key === "encryptionKey") {
          storageKey = "tcs_encryptionkey";
        } else if (key === "syncInterval") {
          storageKey = "tcs_sync_interval";
        } else {
          storageKey = `tcs_dropbox_${key.toLowerCase()}`;
        }

        let value = localStorage.getItem(storageKey);

        // Decrypt sensitive tokens if they're obfuscated
        if (
          (key === "accessToken" || key === "refreshToken") &&
          value?.startsWith("enc::")
        ) {
          if (encryptionKey) {
            try {
              value = this._deobfuscate(value.substring(5), encryptionKey);
            } catch (e) {
              console.warn(
                `[TCS-Dropbox] Could not decrypt key "${key}". It might be corrupted or the encryption key is wrong.`
              );
            }
          } else {
            console.warn(
              `[TCS-Dropbox] Found encrypted key "${key}" but no encryption key is configured.`
            );
          }
        }

        // Parse integer values
        if (key === "syncInterval") {
          stored[key] = parseInt(value) || 15;
        } else if (key === "tokenExpiry") {
          stored[key] = parseInt(value) || 0;
        } else {
          stored[key] = value || "";
        }
      });

      return { ...defaults, ...stored };
    }

    loadExclusions() {
      const exclusions = localStorage.getItem("tcs_sync-exclusions");
      const userExclusions = exclusions
        ? exclusions
            .split(",")
            .map((item) => item.trim())
            .filter(Boolean)
        : [];

      const systemExclusions = [
        "tcs_dropbox_appkey",
        "tcs_dropbox_accesstoken",
        "tcs_dropbox_refreshtoken",
        "tcs_dropbox_tokenexpiry",
        "tcs_encryptionkey",
        "tcs_last-cloud-sync",
        "tcs_last-daily-backup",
        "tcs_backup-size",
        "tcs_sync-exclusions",
        "tcs_local-metadata",
        "tcs_localMigrated",
        "tcs_migrationBackup",
        "tcs_last-tombstone-cleanup",
        "tcs_pkce_verifier",
        "tcs_pkce_state",
        "referrer",
        "TM_useLastVerifiedToken",
        "TM_useStateUpdateHistory",
        "INSTANCE_ID",
        "eruda-console",
      ];

      return [...systemExclusions, ...userExclusions];
    }

    get(key) {
      return this.config[key];
    }

    set(key, value) {
      this.config[key] = value;
    }

    save() {
      const encryptionKey = this.config.encryptionKey;

      Object.keys(this.config).forEach((key) => {
        let storageKey;
        if (key === "encryptionKey") {
          storageKey = "tcs_encryptionkey";
        } else if (key === "syncInterval") {
          storageKey = "tcs_sync_interval";
        } else {
          storageKey = `tcs_dropbox_${key.toLowerCase()}`;
        }

        let valueToStore = this.config[key].toString();

        // Obfuscate sensitive tokens
        if (
          (key === "accessToken" || key === "refreshToken") &&
          valueToStore &&
          encryptionKey
        ) {
          valueToStore = "enc::" + this._obfuscate(valueToStore, encryptionKey);
        }

        localStorage.setItem(storageKey, valueToStore);
      });
    }

    isConfigured() {
      // For Dropbox, we need app key and a valid access token
      return !!(
        this.config.appKey &&
        this.config.accessToken &&
        this.config.encryptionKey
      );
    }

    shouldExclude(key) {
      return (
        this.exclusions.includes(key) ||
        key.startsWith("tcs_") ||
        key.includes("eruda")
      );
    }

    reloadExclusions() {
      this.exclusions = this.loadExclusions();
    }
  }

  /**
   * DropboxAuth - Handles OAuth 2.0 authentication with PKCE
   * This is a NEW class not present in S3 version
   * Implements OAuth 2.0 Authorization Code Flow with PKCE for security
   */
  class DropboxAuth {
    constructor(configManager, logger) {
      this.config = configManager;
      this.logger = logger;
      this.redirectUri = window.location.origin + window.location.pathname;
    }

    /**
     * Generate a cryptographically secure random string for PKCE
     * @param {number} length - Length of the string (43-128 chars for PKCE)
     * @returns {string} - Random string with allowed characters [A-Za-z0-9-._~]
     */
    generateRandomString(length) {
      const charset =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
      const randomValues = new Uint8Array(length);
      crypto.getRandomValues(randomValues);
      return Array.from(randomValues)
        .map((val) => charset[val % charset.length])
        .join("");
    }

    /**
     * Base64 URL encode (without padding)
     * @param {ArrayBuffer} buffer - Buffer to encode
     * @returns {string} - Base64 URL encoded string
     */
    base64URLEncode(buffer) {
      const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
      return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    }

    /**
     * Generate PKCE code verifier and challenge
     * @returns {Promise<Object>} - { verifier, challenge }
     */
    async generatePKCE() {
      const verifier = this.generateRandomString(128);
      const encoder = new TextEncoder();
      const data = encoder.encode(verifier);
      const hash = await crypto.subtle.digest("SHA-256", data);
      const challenge = this.base64URLEncode(hash);

      return { verifier, challenge };
    }

    /**
     * Build Dropbox authorization URL with PKCE
     * @returns {Promise<string>} - Authorization URL
     */
    async getAuthUrl() {
      const { verifier, challenge } = await this.generatePKCE();
      const state = this.generateRandomString(32);

      // Store verifier and state for later verification
      localStorage.setItem("tcs_pkce_verifier", verifier);
      localStorage.setItem("tcs_pkce_state", state);

      const params = new URLSearchParams({
        client_id: this.config.get("appKey"),
        response_type: "code",
        code_challenge: challenge,
        code_challenge_method: "S256",
        redirect_uri: this.redirectUri,
        state: state,
        token_access_type: "offline", // Request refresh token
      });

      return `https://www.dropbox.com/oauth2/authorize?${params.toString()}`;
    }

    /**
     * Exchange authorization code for access token
     * @param {string} code - Authorization code from Dropbox
     * @returns {Promise<Object>} - { accessToken, refreshToken, expiresIn }
     */
    async exchangeCodeForToken(code) {
      const verifier = localStorage.getItem("tcs_pkce_verifier");
      if (!verifier) {
        throw new Error("PKCE verifier not found. Please restart authentication.");
      }

      try {
        const response = await fetch("https://api.dropboxapi.com/oauth2/token", {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            code: code,
            grant_type: "authorization_code",
            code_verifier: verifier,
            client_id: this.config.get("appKey"),
            redirect_uri: this.redirectUri,
          }),
        });

        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(
            `Token exchange failed: ${errorData.error_description || errorData.error}`
          );
        }

        const data = await response.json();

        // Clear stored PKCE data
        localStorage.removeItem("tcs_pkce_verifier");
        localStorage.removeItem("tcs_pkce_state");

        this.logger.log("success", "Successfully obtained access token");

        return {
          accessToken: data.access_token,
          refreshToken: data.refresh_token,
          expiresIn: data.expires_in, // Typically 14400 seconds (4 hours)
        };
      } catch (error) {
        this.logger.log("error", "Token exchange error", error.message);
        throw error;
      }
    }

    /**
     * Refresh access token using refresh token
     * @param {string} refreshToken - Refresh token
     * @returns {Promise<Object>} - { accessToken, expiresIn }
     */
    async refreshAccessToken(refreshToken) {
      try {
        const response = await fetch("https://api.dropboxapi.com/oauth2/token", {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: refreshToken,
            client_id: this.config.get("appKey"),
          }),
        });

        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(
            `Token refresh failed: ${errorData.error_description || errorData.error}`
          );
        }

        const data = await response.json();

        this.logger.log("success", "Successfully refreshed access token");

        return {
          accessToken: data.access_token,
          expiresIn: data.expires_in,
        };
      } catch (error) {
        this.logger.log("error", "Token refresh error", error.message);
        throw error;
      }
    }

    /**
     * Get a valid access token, refreshing if necessary
     * @returns {Promise<string>} - Valid access token
     */
    async getValidToken() {
      const accessToken = this.config.get("accessToken");
      const tokenExpiry = this.config.get("tokenExpiry");
      const now = Date.now();

      // Check if token is expired or about to expire (within 5 minutes)
      if (now >= tokenExpiry - 5 * 60 * 1000) {
        this.logger.log("info", "Access token expired or expiring soon, refreshing...");
        const refreshToken = this.config.get("refreshToken");

        if (!refreshToken) {
          throw new Error("No refresh token available. Please re-authenticate.");
        }

        const newTokens = await this.refreshAccessToken(refreshToken);

        // Update stored tokens
        this.config.set("accessToken", newTokens.accessToken);
        this.config.set("tokenExpiry", now + newTokens.expiresIn * 1000);
        this.config.save();

        return newTokens.accessToken;
      }

      return accessToken;
    }

    /**
     * Check if we're being redirected back from OAuth
     * @returns {string|null} - Authorization code if present, null otherwise
     */
    checkForAuthCode() {
      const urlParams = new URLSearchParams(window.location.search);
      const code = urlParams.get("code");
      const state = urlParams.get("state");
      const error = urlParams.get("error");

      if (error) {
        this.logger.log("error", `OAuth error: ${error}`, urlParams.get("error_description"));
        return null;
      }

      if (code && state) {
        // Verify state to prevent CSRF
        const storedState = localStorage.getItem("tcs_pkce_state");
        if (state !== storedState) {
          this.logger.log("error", "State mismatch - possible CSRF attack");
          return null;
        }

        this.logger.log("info", "Authorization code received from Dropbox");
        return code;
      }

      return null;
    }
  }

  /**
   * Logger class - UNCHANGED from S3 version
   * Handles logging with mobile debug console support
   */
  class Logger {
    constructor() {
      const urlParams = new URLSearchParams(window.location.search);
      this.enabled = urlParams.get("log") === "true" || urlParams.has("log");
      this.icons = {
        info: "ℹ️",
        success: "✅",
        warning: "⚠️",
        error: "❌",
        start: "🔄",
        skip: "⏭️",
      };
      if (this.enabled) {
        this.loadEruda();
      }
    }
    loadEruda() {
      const isMobile =
        /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(
          navigator.userAgent
        );
      if (!isMobile) return;
      if (document.getElementById("eruda-script")) return;
      const script = document.createElement("script");
      script.id = "eruda-script";
      script.src = "https://cdn.jsdelivr.net/npm/eruda@3.0.1/eruda.min.js";
      script.onload = () => {
        window.eruda?.init();
      };
      document.head.appendChild(script);
    }
    destroyEruda() {
      window.eruda?.destroy();
      document.getElementById("eruda-script")?.remove();
    }
    log(type, message, data = null) {
      if (!this.enabled) return;
      const timestamp = new Date().toLocaleTimeString();
      const icon = this.icons[type] || "ℹ️";
      const logMessage = `${icon} [${timestamp}] ${message}`;
      switch (type) {
        case "error":
          console.error(logMessage, data || "");
          break;
        case "warning":
          console.warn(logMessage, data || "");
          break;
        default:
          console.log(logMessage, data || "");
      }
    }
    setEnabled(enabled) {
      this.enabled = enabled;
      const url = new URL(window.location);
      if (enabled) {
        url.searchParams.set("log", "");
        this.loadEruda();
      } else {
        url.searchParams.delete("log");
        this.destroyEruda();
      }
      window.history.replaceState({}, "", url);
    }
  }

  /**
   * DataService - UNCHANGED from S3 version
   * Manages access to IndexedDB and localStorage
   * Memory-efficient data streaming and tombstone management
   */
  class DataService {
    constructor(configManager, logger, operationQueue = null) {
      this.config = configManager;
      this.logger = logger;
      this.operationQueue = operationQueue;
      this.dbPromise = null;
      this.streamBatchSize = 1000;
      this.memoryThreshold = 100 * 1024 * 1024;
      this.throttleDelay = 10;
    }
    async getDB() {
      if (!this.dbPromise) {
        this.dbPromise = new Promise((resolve, reject) => {
          const request = indexedDB.open("keyval-store");
          request.onsuccess = () => resolve(request.result);
          request.onerror = () => reject(new Error("Failed to open IndexedDB"));
        });
      }
      return this.dbPromise;
    }
    async estimateDataSize() {
      let totalSize = 0;
      let itemCount = 0;
      const db = await this.getDB();
      const transaction = db.transaction(["keyval"], "readonly");
      const store = transaction.objectStore("keyval");
      await new Promise((resolve) => {
        const request = store.openCursor();
        request.onsuccess = (event) => {
          const cursor = event.target.result;
          if (cursor) {
            const key = cursor.key;
            const value = cursor.value;
            if (
              typeof key === "string" &&
              value !== undefined &&
              !this.config.shouldExclude(key)
            ) {
              try {
                const itemSize = JSON.stringify(value).length * 2;
                totalSize += itemSize;
                itemCount++;
              } catch (e) {
                this.logger.log("warning", `Error estimating size for ${key}`);
              }
            }
            cursor.continue();
          } else {
            resolve();
          }
        };
        request.onerror = () => resolve();
      });
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && !this.config.shouldExclude(key)) {
          const value = localStorage.getItem(key);
          if (value !== null) {
            totalSize += value.length * 2;
            itemCount++;
          }
        }
      }
      return { totalSize, itemCount };
    }
    async *streamAllItems() {
      const batchSize = this.streamBatchSize;
      let batch = [];
      let batchSize_bytes = 0;
      const processItem = (item) => {
        const estimatedSize = this.estimateItemSize(item.data);
        if (
          batchSize_bytes + estimatedSize > this.memoryThreshold &&
          batch.length > 0
        ) {
          const currentBatch = [...batch];
          batch = [item];
          batchSize_bytes = estimatedSize;
          return currentBatch;
        }
        batch.push(item);
        batchSize_bytes += estimatedSize;
        if (batch.length >= batchSize) {
          const currentBatch = [...batch];
          batch = [];
          batchSize_bytes = 0;
          return currentBatch;
        }
        return null;
      };
      const db = await this.getDB();
      const transaction = db.transaction(["keyval"], "readonly");
      const store = transaction.objectStore("keyval");
      await new Promise((resolve) => {
        const request = store.openCursor();
        request.onsuccess = (event) => {
          const cursor = event.target.result;
          if (cursor) {
            const key = cursor.key;
            const value = cursor.value;
            if (
              typeof key === "string" &&
              value !== undefined &&
              !this.config.shouldExclude(key)
            ) {
              const item = { id: key, data: value, type: "idb" };
              const batchToYield = processItem(item);
              if (batchToYield) {
                this.streamYield(batchToYield);
              }
            }
            cursor.continue();
          } else {
            resolve();
          }
        };
        request.onerror = () => resolve();
      });
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && !this.config.shouldExclude(key)) {
          const value = localStorage.getItem(key);
          if (value !== null) {
            const item = { id: key, data: { key, value }, type: "ls" };
            const batchToYield = processItem(item);
            if (batchToYield) {
              yield batchToYield;
            }
          }
        }
      }
      if (batch.length > 0) {
        yield batch;
      }
    }
    streamYield = null;
    async *streamAllItemsInternal() {
      const batchSize = this.streamBatchSize;
      let batch = [];
      let batchSize_bytes = 0;
      let db = null;
      let transaction = null;
      let pendingBatches = [];
      let currentBatchIndex = 0;
      try {
        const processItem = (item) => {
          try {
            const estimatedSize = this.estimateItemSize(item.data);
            if (
              batchSize_bytes + estimatedSize > this.memoryThreshold &&
              batch.length > 0
            ) {
              const currentBatch = [...batch];
              batch = [item];
              batchSize_bytes = estimatedSize;
              return currentBatch;
            }
            batch.push(item);
            batchSize_bytes += estimatedSize;
            if (batch.length >= batchSize) {
              const currentBatch = [...batch];
              batch = [];
              batchSize_bytes = 0;
              return currentBatch;
            }
            return null;
          } catch (error) {
            this.logger.log(
              "warning",
              `Error processing item: ${error.message}`
            );
            return null;
          }
        };
        db = await this.getDB();
        transaction = db.transaction(["keyval"], "readonly");
        const store = transaction.objectStore("keyval");
        let idbProcessed = 0;
        await new Promise((resolve, reject) => {
          const request = store.openCursor();
          request.onsuccess = (event) => {
            try {
              const cursor = event.target.result;
              if (cursor) {
                const key = cursor.key;
                const value = cursor.value;
                if (
                  typeof key === "string" &&
                  value !== undefined &&
                  !this.config.shouldExclude(key)
                ) {
                  const item = { id: key, data: value, type: "idb" };
                  const batchToYield = processItem(item);
                  if (batchToYield) {
                    pendingBatches.push(batchToYield);
                    if (pendingBatches.length >= 10) {
                      this.logger.log(
                        "warning",
                        `Large number of pending batches (${pendingBatches.length}), potential memory issue`
                      );
                    }
                  }
                  idbProcessed++;
                  if (idbProcessed % 5000 === 0) {
                    this.logger.log(
                      "info",
                      `Processed ${idbProcessed} IndexedDB items`
                    );
                  }
                }
                cursor.continue();
              } else {
                resolve();
              }
            } catch (error) {
              this.logger.log(
                "error",
                `Error in cursor processing: ${error.message}`
              );
              reject(error);
            }
          };
          request.onerror = () => {
            this.logger.log("error", "IndexedDB cursor error");
            reject(request.error);
          };
        });
        for (let i = 0; i < pendingBatches.length; i++) {
          yield pendingBatches[i];
          pendingBatches[i] = null;
          currentBatchIndex = i + 1;
          if (i % 5 === 0) {
            await this.forceGarbageCollection();
          }
        }
        pendingBatches = null;
        let lsProcessed = 0;
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          if (key && !this.config.shouldExclude(key)) {
            const value = localStorage.getItem(key);
            if (value !== null) {
              const item = { id: key, data: { key, value }, type: "ls" };
              const batchToYield = processItem(item);
              if (batchToYield) {
                yield batchToYield;
                await this.forceGarbageCollection();
              }
              lsProcessed++;
              if (lsProcessed % 1000 === 0) {
                this.logger.log(
                  "info",
                  `Processed ${lsProcessed} localStorage items`
                );
              }
            }
          }
        }
        if (batch && batch.length > 0) {
          yield batch;
          await this.forceGarbageCollection();
        }
      } catch (error) {
        this.logger.log(
          "error",
          `Error in streamAllItemsInternal: ${error.message}`
        );
        throw error;
      } finally {
        try {
          if (pendingBatches) {
            for (let i = currentBatchIndex; i < pendingBatches.length; i++) {
              pendingBatches[i] = null;
            }
            pendingBatches = null;
          }
          batch = null;
          transaction = null;
          db = null;
          await this.forceGarbageCollection();
        } catch (cleanupError) {
          this.logger.log("warning", `Cleanup error: ${cleanupError.message}`);
        }
      }
    }
    async getAllItemsEfficient() {
      const { totalSize } = await this.estimateDataSize();
      if (totalSize > this.memoryThreshold) {
        this.logger.log(
          "info",
          `Large dataset detected (${this.formatSize(
            totalSize
          )}), using memory-efficient processing`
        );
        return this.streamAllItemsInternal();
      } else {
        this.logger.log(
          "info",
          `Small dataset (${this.formatSize(
            totalSize
          )}), using standard loading`
        );
        return [await this.getAllItems()];
      }
    }
    estimateItemSize(data) {
      if (typeof data === "string") return data.length * 2;
      if (data && typeof data === "object") {
        return Object.keys(data).length * 50;
      }
      return 1000;
    }
    formatSize(bytes) {
      if (bytes === 0) return "0 B";
      const k = 1024;
      const sizes = ["B", "KB", "MB", "GB"];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    }
    async forceGarbageCollection() {
      if (window?.gc) {
        window.gc();
      } else if (typeof global !== "undefined" && global?.gc) {
        global.gc();
      }
      await new Promise((resolve) => setTimeout(resolve, this.throttleDelay));
    }
    async getAllItems() {
      const items = new Map();
      const db = await this.getDB();
      const transaction = db.transaction(["keyval"], "readonly");
      const store = transaction.objectStore("keyval");
      let totalIDB = 0;
      let includedIDB = 0;
      let excludedIDB = 0;
      await new Promise((resolve) => {
        const request = store.openCursor();
        request.onsuccess = (event) => {
          const cursor = event.target.result;
          if (cursor) {
            const key = cursor.key;
            const value = cursor.value;
            totalIDB++;
            if (
              typeof key === "string" &&
              value !== undefined &&
              !this.config.shouldExclude(key)
            ) {
              items.set(key, {
                id: key,
                data: value,
                type: "idb",
              });
              includedIDB++;
            } else {
              excludedIDB++;
            }
            cursor.continue();
          } else {
            resolve();
          }
        };
        request.onerror = () => resolve();
      });
      const urlParams = new URLSearchParams(window.location.search);
      const debugEnabled =
        urlParams.get("log") === "true" || urlParams.has("log");
      let totalLS = 0;
      let excludedLS = 0;
      let includedLS = 0;
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        totalLS++;
        if (key && !this.config.shouldExclude(key)) {
          const value = localStorage.getItem(key);
          if (value !== null) {
            items.set(key, { id: key, data: { key, value }, type: "ls" });
            includedLS++;
          }
        } else {
          excludedLS++;
        }
      }
      if (debugEnabled) {
        console.log(
          `📊 IndexedDB Stats: Total=${totalIDB}, Included=${includedIDB}, Excluded=${excludedIDB}`
        );
        console.log(
          `📊 localStorage Stats: Total=${totalLS}, Included=${includedLS}, Excluded=${excludedLS}`
        );
        console.log(`📊 Total items to sync: ${items.size} (IDB + LS)`);
      }
      const chatItems = Array.from(items.keys()).filter((id) =>
        id.startsWith("CHAT_")
      );
      const otherItems = Array.from(items.keys()).filter(
        (id) => !id.startsWith("CHAT_")
      );
      this.logger.log("success", "📋 Retrieved all items for deletion check", {
        totalItems: items.size,
        idbStats: {
          total: totalIDB,
          included: includedIDB,
          excluded: excludedIDB,
        },
        lsStats: { total: totalLS, included: includedLS, excluded: excludedLS },
        chatCount: chatItems.length,
        otherCount: otherItems.length,
      });
      return Array.from(items.values());
    }
    async getAllItemKeys() {
      const itemKeys = new Set();
      const db = await this.getDB();
      const transaction = db.transaction(["keyval"], "readonly");
      const store = transaction.objectStore("keyval");
      await new Promise((resolve) => {
        const request = store.openKeyCursor();
        request.onsuccess = (event) => {
          const cursor = event.target.result;
          if (cursor) {
            const key = cursor.key;
            if (typeof key === "string" && !this.config.shouldExclude(key)) {
              itemKeys.add(key);
            }
            cursor.continue();
          } else {
            resolve();
          }
        };
        request.onerror = () => resolve();
      });
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && !this.config.shouldExclude(key)) {
          itemKeys.add(key);
        }
      }
      return itemKeys;
    }
    async getItem(itemId, type) {
      if (type === "idb") {
        const db = await this.getDB();
        const transaction = db.transaction(["keyval"], "readonly");
        const store = transaction.objectStore("keyval");
        return new Promise((resolve) => {
          const request = store.get(itemId);
          request.onsuccess = () => {
            const result = request.result;
            resolve(result || null);
          };
          request.onerror = () => resolve(null);
        });
      } else if (type === "ls") {
        const value = localStorage.getItem(itemId);
        return value !== null ? { key: itemId, value } : null;
      }
      return null;
    }
    async saveItem(item, type, itemKey = null) {
      if (type === "idb") {
        const db = await this.getDB();
        const transaction = db.transaction(["keyval"], "readwrite");
        const store = transaction.objectStore("keyval");
        const itemId = itemKey || item?.id;
        const itemData = item;
        return new Promise((resolve) => {
          const request = store.put(itemData, itemId);
          request.onsuccess = () => resolve(true);
          request.onerror = () => resolve(false);
        });
      } else if (type === "ls") {
        try {
          localStorage.setItem(item.key, item.value);
          return true;
        } catch {
          return false;
        }
      }
      return false;
    }
    async deleteItem(itemId, type) {
      const success = await this.performDelete(itemId, type);
      if (success) {
        this.createTombstone(itemId, type, "manual-delete");
      }
      return success;
    }
    async performDelete(itemId, type) {
      if (type === "idb") {
        const db = await this.getDB();
        const transaction = db.transaction(["keyval"], "readwrite");
        const store = transaction.objectStore("keyval");
        return new Promise((resolve) => {
          const request = store.delete(itemId);
          request.onsuccess = () => resolve(true);
          request.onerror = () => resolve(false);
        });
      } else if (type === "ls") {
        try {
          localStorage.removeItem(itemId);
          return true;
        } catch {
          return false;
        }
      }
      return false;
    }
    createTombstone(itemId, type, source = "unknown") {
      const orchestrator = window.cloudSyncApp?.syncOrchestrator;
      if (!orchestrator) {
        this.logger.log(
          "error",
          "❌ Cannot create tombstone: SyncOrchestrator not found."
        );
        return null;
      }
      const timestamp = Date.now();
      const tombstone = {
        deleted: timestamp,
        deletedAt: timestamp,
        type: type,
        source: source,
        tombstoneVersion: 1,
      };
      this.logger.log("start", "🪦 Creating tombstone in metadata", {
        itemId: itemId,
        type: type,
        source: source,
      });
      const existingItem = orchestrator.metadata.items[itemId];
      if (existingItem?.deleted) {
        tombstone.tombstoneVersion = (existingItem.tombstoneVersion || 0) + 1;
        this.logger.log(
          "info",
          "📈 Incrementing existing tombstone version in metadata",
          {
            newVersion: tombstone.tombstoneVersion,
          }
        );
      }
      orchestrator.metadata.items[itemId] = {
        ...tombstone,
        synced: 0,
      };
      orchestrator.saveMetadata();
      this.logger.log("success", "✅ Tombstone created in metadata", {
        itemId: itemId,
        version: tombstone.tombstoneVersion,
      });
      this.operationQueue?.add(
        `tombstone-sync-${itemId}`,
        () => this.syncTombstone(itemId),
        "high"
      );
      return tombstone;
    }
    getTombstoneFromStorage(itemId) {
      try {
        const storageKey = `tcs_tombstone_${itemId}`;
        const stored = localStorage.getItem(storageKey);
        if (stored) {
          const tombstone = JSON.parse(stored);
          return tombstone;
        } else {
          return null;
        }
      } catch (error) {
        this.logger.log("error", "❌ Error reading tombstone from storage", {
          itemId: itemId,
          error: error.message,
        });
        return null;
      }
    }
    saveTombstoneToStorage(itemId, tombstone) {
      try {
        const storageKey = `tcs_tombstone_${itemId}`;
        localStorage.setItem(storageKey, JSON.stringify(tombstone));
        const verification = localStorage.getItem(storageKey);
        if (verification) {
          this.logger.log(
            "success",
            "✅ Tombstone successfully saved and verified",
            {
              itemId: itemId,
              storageKey: storageKey,
            }
          );
        } else {
          this.logger.log("error", "❌ Tombstone save verification failed", {
            itemId: itemId,
            storageKey: storageKey,
          });
        }
      } catch (error) {
        this.logger.log("error", "❌ Failed to save tombstone to storage", {
          itemId: itemId,
          error: error.message,
        });
      }
    }
    getAllTombstones() {
      const tombstones = new Map();
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key?.startsWith("tcs_tombstone_")) {
          const itemId = key.replace("tcs_tombstone_", "");
          try {
            const tombstone = JSON.parse(localStorage.getItem(key));
            tombstones.set(itemId, tombstone);
          } catch {
            continue;
          }
        }
      }
      return tombstones;
    }
    async syncTombstone(itemId) {
      this.logger.log("info", `🔄 Triggering sync for tombstone ${itemId}`);
      if (window.cloudSyncApp?.syncOrchestrator) {
        try {
          await window.cloudSyncApp.syncOrchestrator.syncToCloud();
          this.logger.log(
            "success",
            `✅ Tombstone sync completed for ${itemId}`
          );
        } catch (error) {
          this.logger.log(
            "error",
            `❌ Tombstone sync failed for ${itemId}`,
            error.message
          );
          throw error;
        }
      } else {
        this.logger.log(
          "warning",
          `⚠️ Sync orchestrator not available for ${itemId}`
        );
      }
    }
    cleanup() {
      this.logger?.log("info", "🧹 DataService cleanup starting");
      try {
        if (this.dbPromise) {
          this.dbPromise
            .then((db) => {
              if (db) {
                db.close();
                this.logger?.log("info", "✅ IndexedDB connection closed");
              }
            })
            .catch((error) => {
              this.logger?.log(
                "warning",
                `IndexedDB close error: ${error.message}`
              );
            });
        }
        this.dbPromise = null;
        this.streamYield = null;
        this.config = null;
        this.operationQueue = null;
        if (this.forceGarbageCollection) {
          this.forceGarbageCollection().catch(() => {});
        }
        this.logger?.log("success", "✅ DataService cleanup completed");
        this.logger = null;
      } catch (error) {
        console.warn("DataService cleanup error:", error);
      }
    }
  }
  class CryptoService {
    constructor(configManager, logger) {
      this.config = configManager;
      this.logger = logger;
      this.keyCache = new Map();
      this.maxCacheSize = 10;
      this.lastCacheCleanup = Date.now();
      this.largeArrayKeys = ["TM_useUserCharacters"];
    }
    async deriveKey(password) {
      const now = Date.now();
      if (now - this.lastCacheCleanup > 30 * 60 * 1000) {
        this.cleanupKeyCache();
        this.lastCacheCleanup = now;
      }
      if (this.keyCache.has(password)) return this.keyCache.get(password);
      if (this.keyCache.size >= this.maxCacheSize) {
        const firstKey = this.keyCache.keys().next().value;
        this.keyCache.delete(firstKey);
      }
      const data = new TextEncoder().encode(password);
      const hash = await crypto.subtle.digest("SHA-256", data);
      const key = await crypto.subtle.importKey(
        "raw",
        hash,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
      );
      this.keyCache.set(password, key);
      return key;
    }
    cleanupKeyCache() {
      if (this.keyCache.size > this.maxCacheSize / 2) {
        const keysToRemove = Math.floor(this.keyCache.size / 2);
        const keyIterator = this.keyCache.keys();
        for (let i = 0; i < keysToRemove; i++) {
          const oldestKey = keyIterator.next().value;
          if (oldestKey) {
            this.keyCache.delete(oldestKey);
          }
        }
      }
    }
    _createJsonStreamForArray(array) {
      let i = 0;
      const encoder = new TextEncoder();
      return new ReadableStream({
        start(controller) {
          controller.enqueue(encoder.encode("["));
        },
        pull(controller) {
          if (i >= array.length) {
            controller.enqueue(encoder.encode("]"));
            controller.close();
            return;
          }

          try {
            const chunk = JSON.stringify(array[i]);
            if (i < array.length - 1) {
              controller.enqueue(encoder.encode(chunk + ","));
            } else {
              controller.enqueue(encoder.encode(chunk));
            }
            i++;
          } catch (e) {
            this.logger.log(
              "error",
              `Streaming serialization failed for element ${i}`,
              e
            );
            controller.error(e);
          }
        },
      });
    }
    async encrypt(data, key = null) {
      const encryptionKey = this.config.get("encryptionKey");
      if (!encryptionKey) throw new Error("No encryption key configured");

      const cryptoKey = await this.deriveKey(encryptionKey);
      let dataStream;

      // Check if we should use streaming serialization
      if (key && this.largeArrayKeys.includes(key) && Array.isArray(data)) {
        this.logger.log(
          "info",
          `Using streaming serialization for large array: ${key}`
        );
        dataStream = this._createJsonStreamForArray(data);
      } else {
        // Use the standard in-memory method for other items
        const encodedData = new TextEncoder().encode(JSON.stringify(data));
        dataStream = new Blob([encodedData]).stream();
      }

      let processedStream = dataStream;
      try {
        if (window.CompressionStream) {
          processedStream = dataStream.pipeThrough(
            new CompressionStream("deflate-raw")
          );
        } else {
          this.logger.log(
            "warning",
            "CompressionStream API not supported, uploading uncompressed."
          );
        }
      } catch (e) {
        this.logger.log(
          "warning",
          "Could not compress data, uploading uncompressed.",
          e
        );
      }

      const finalData = new Uint8Array(
        await new Response(processedStream).arrayBuffer()
      );

      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        cryptoKey,
        finalData
      );

      const result = new Uint8Array(iv.length + encrypted.byteLength);
      result.set(iv, 0);
      result.set(new Uint8Array(encrypted), iv.length);
      return result;
    }
    async encryptBytes(data) {
      const encryptionKey = this.config.get("encryptionKey");
      if (!encryptionKey) throw new Error("No encryption key configured");
      const key = await this.deriveKey(encryptionKey);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        data
      );
      const result = new Uint8Array(iv.length + encrypted.byteLength);
      result.set(iv, 0);
      result.set(new Uint8Array(encrypted), iv.length);
      return result;
    }
    async decrypt(encryptedData) {
      const encryptionKey = this.config.get("encryptionKey");
      if (!encryptionKey) throw new Error("No encryption key configured");
      const key = await this.deriveKey(encryptionKey);
      const iv = encryptedData.slice(0, 12);
      const data = encryptedData.slice(12);
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        data
      );
      try {
        if (window.DecompressionStream) {
          const stream = new Blob([decrypted])
            .stream()
            .pipeThrough(new DecompressionStream("deflate-raw"));
          const text = await new Response(stream).text();
          return JSON.parse(text);
        } else {
          this.logger.log(
            "warning",
            "DecompressionStream API not supported, decoding as text."
          );
          return JSON.parse(new TextDecoder().decode(decrypted));
        }
      } catch (e) {
        return JSON.parse(new TextDecoder().decode(decrypted));
      }
    }
    async decryptBytes(encryptedData) {
      const encryptionKey = this.config.get("encryptionKey");
      if (!encryptionKey) throw new Error("No encryption key configured");
      const key = await this.deriveKey(encryptionKey);
      const iv = encryptedData.slice(0, 12);
      const data = encryptedData.slice(12);
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        data
      );
      return new Uint8Array(decrypted);
    }
    cleanup() {
      this.logger?.log("info", "🧹 CryptoService cleanup starting");
      try {
        if (this.keyCache) {
          this.keyCache.clear();
        }
        this.keyCache = null;
        this.lastCacheCleanup = 0;
        this.config = null;
        this.logger?.log("success", "✅ CryptoService cleanup completed");
        this.logger = null;
      } catch (error) {
        console.warn("CryptoService cleanup error:", error);
      }
    }
  }

  /**
   * DropboxService - Replaces S3Service
   * Handles all Dropbox API interactions with file upload/download, batch operations, and error handling
   * Key differences from S3Service:
   * - Uses Dropbox JavaScript SDK instead of AWS SDK
   * - All paths must start with '/' (S3 paths don't)
   * - Different error codes and response structures
   * - Batch operations use async job pattern
   * - Token management integrated via DropboxAuth
   */
  class DropboxService {
    constructor(configManager, cryptoService, logger, dropboxAuth = null) {
      this.config = configManager;
      this.crypto = cryptoService;
      this.logger = logger;
      this.auth = dropboxAuth;
      this.client = null;
      this.sdkLoaded = false;
    }

    /**
     * Initialize Dropbox client
     */
    async initialize() {
      if (!this.config.isConfigured()) {
        throw new Error("Dropbox configuration incomplete");
      }

      await this.loadSDK();

      // Get a valid access token (refreshes if needed)
      const accessToken = this.auth
        ? await this.auth.getValidToken()
        : this.config.get("accessToken");

      if (!accessToken) {
        throw new Error("No valid access token available");
      }

      // Initialize Dropbox client
      this.client = new Dropbox.Dropbox({ accessToken, fetch });

      this.logger.log("success", "Dropbox client initialized");
    }

    /**
     * Load Dropbox SDK dynamically
     */
    async loadSDK() {
      if (this.sdkLoaded || window.Dropbox) {
        this.sdkLoaded = true;
        return;
      }

      return new Promise((resolve, reject) => {
        const script = document.createElement("script");
        script.src = "https://unpkg.com/dropbox@10.34.0/dist/Dropbox-sdk.min.js";
        script.onload = () => {
          this.sdkLoaded = true;
          this.logger.log("success", "Dropbox SDK loaded");
          resolve();
        };
        script.onerror = () => reject(new Error("Failed to load Dropbox SDK"));
        document.head.appendChild(script);
      });
    }

    /**
     * Convert S3-style path to Dropbox path
     * S3: "metadata.json" or "items/CHAT_xxx.enc"
     * Dropbox: "/metadata.json" or "/items/CHAT_xxx.enc"
     * @param {string} key - S3-style key
     * @returns {string} - Dropbox path with leading /
     */
    toDropboxPath(key) {
      if (!key || key === "") return "";
      return key.startsWith("/") ? key : `/${key}`;
    }

    /**
     * Extract error details from Dropbox API errors
     * @param {Error} error - Dropbox error object
     * @returns {string} - Detailed error description
     */
    extractErrorDetails(error) {
      if (!error) return "Unknown error";

      const details = [];

      if (error.message) {
        details.push(`Message: ${error.message}`);
      }

      if (error.status) {
        details.push(`Status: ${error.status}`);
      }

      if (error.error) {
        // Dropbox error object
        if (error.error[".tag"]) {
          details.push(`Type: ${error.error[".tag"]}`);
        }
        if (error.error.error_summary) {
          details.push(`Summary: ${error.error.error_summary}`);
        }
        if (error.error.path && error.error.path[".tag"]) {
          details.push(`Path Error: ${error.error.path[".tag"]}`);
        }
      }

      // Rate limiting info
      if (error.status === 429 && error.headers) {
        const retryAfter = error.headers.get("retry-after");
        if (retryAfter) {
          details.push(`Retry-After: ${retryAfter}s`);
        }
      }

      return details.length > 0 ? details.join(" | ") : "Unknown Dropbox error";
    }

    /**
     * Retry wrapper for Dropbox operations
     * @param {Function} operation - Async function to retry
     * @param {number} maxRetries - Maximum retry attempts
     * @returns {Promise<any>} - Operation result
     */
    async withRetry(operation, maxRetries = 3) {
      let lastError;
      for (let attempt = 0; attempt <= maxRetries; attempt++) {
        try {
          return await operation();
        } catch (error) {
          lastError = error;

          // Don't retry on not found errors
          if (
            error.status === 409 &&
            error.error?.path?.[".tag"] === "not_found"
          ) {
            throw error;
          }

          // Don't retry on authentication errors
          if (error.status === 401) {
            throw error;
          }

          if (attempt === maxRetries) break;

          // Calculate delay - use Retry-After header if available
          let delay = Math.min(1000 * Math.pow(2, attempt), 10000);
          if (
            error.status === 429 &&
            error.headers?.get &&
            error.headers.get("retry-after")
          ) {
            delay = parseInt(error.headers.get("retry-after")) * 1000;
          }

          const errorDetails = this.extractErrorDetails(error);
          this.logger.log(
            "warning",
            `Retry ${attempt + 1}/${maxRetries} in ${delay}ms - ${errorDetails}`
          );

          await new Promise((resolve) => setTimeout(resolve, delay));
        }
      }

      throw lastError;
    }

    /**
     * Upload a file to Dropbox
     * @param {string} key - File path (S3-style, will be converted)
     * @param {*} data - Data to upload
     * @param {boolean} isMetadata - Whether this is metadata.json (no encryption)
     * @param {string} itemKey - Item key for encryption context
     * @returns {Promise<Object>} - Upload result
     */
    async upload(key, data, isMetadata = false, itemKey = null) {
      return this.withRetry(async () => {
        try {
          const path = this.toDropboxPath(key);

          // Prepare body
          const body = isMetadata
            ? JSON.stringify(data)
            : await this.crypto.encrypt(data, itemKey || key);

          // Ensure we have a valid token
          if (this.auth) {
            const accessToken = await this.auth.getValidToken();
            this.client = new Dropbox.Dropbox({ accessToken, fetch });
          }

          // Upload to Dropbox
          const result = await this.client.filesUpload({
            path: path,
            contents: body,
            mode: { ".tag": "overwrite" },
            autorename: false,
            mute: true,
          });

          this.logger.log("success", `Uploaded ${key}`, {
            path: result.result.path_display,
            size: result.result.size,
          });

          return result.result;
        } catch (error) {
          this.logger.log(
            "error",
            `Failed to upload ${key}: ${this.extractErrorDetails(error)}`
          );
          throw error;
        }
      });
    }

    /**
     * Upload raw data without encryption
     * @param {string} key - File path
     * @param {*} data - Raw data
     * @returns {Promise<Object>} - Upload result
     */
    async uploadRaw(key, data) {
      return this.withRetry(async () => {
        try {
          const path = this.toDropboxPath(key);

          if (this.auth) {
            const accessToken = await this.auth.getValidToken();
            this.client = new Dropbox.Dropbox({ accessToken, fetch });
          }

          const result = await this.client.filesUpload({
            path: path,
            contents: data,
            mode: { ".tag": "overwrite" },
            autorename: false,
            mute: true,
          });

          this.logger.log("success", `Uploaded raw ${key}`, {
            size: result.result.size,
          });

          return result.result;
        } catch (error) {
          this.logger.log(
            "error",
            `Failed to upload raw ${key}: ${this.extractErrorDetails(error)}`
          );
          throw error;
        }
      });
    }

    /**
     * Download a file from Dropbox
     * @param {string} key - File path
     * @param {boolean} isMetadata - Whether this is metadata.json (no decryption)
     * @returns {Promise<*>} - Decrypted data
     */
    async download(key, isMetadata = false) {
      return this.withRetry(async () => {
        const path = this.toDropboxPath(key);

        if (this.auth) {
          const accessToken = await this.auth.getValidToken();
          this.client = new Dropbox.Dropbox({ accessToken, fetch });
        }

        const result = await this.client.filesDownload({ path });

        // Get file blob and convert to appropriate format
        const fileBlob = result.result.fileBlob;
        const arrayBuffer = await fileBlob.arrayBuffer();

        if (isMetadata) {
          const text = new TextDecoder().decode(arrayBuffer);
          return JSON.parse(text);
        } else {
          const data = new Uint8Array(arrayBuffer);
          return await this.crypto.decrypt(data);
        }
      });
    }

    /**
     * Download raw file without decryption
     * @param {string} key - File path
     * @returns {Promise<Uint8Array>} - Raw file data
     */
    async downloadRaw(key) {
      return this.withRetry(async () => {
        const path = this.toDropboxPath(key);

        if (this.auth) {
          const accessToken = await this.auth.getValidToken();
          this.client = new Dropbox.Dropbox({ accessToken, fetch });
        }

        const result = await this.client.filesDownload({ path });
        const fileBlob = result.result.fileBlob;
        const arrayBuffer = await fileBlob.arrayBuffer();

        return new Uint8Array(arrayBuffer);
      });
    }

    /**
     * Delete a file from Dropbox
     * @param {string} key - File path
     * @returns {Promise<void>}
     */
    async delete(key) {
      return this.withRetry(async () => {
        const path = this.toDropboxPath(key);

        if (this.auth) {
          const accessToken = await this.auth.getValidToken();
          this.client = new Dropbox.Dropbox({ accessToken, fetch });
        }

        await this.client.filesDeleteV2({ path });
        this.logger.log("success", `Deleted ${key}`);
      });
    }

    /**
     * List files with a given prefix
     * Handles pagination automatically
     * @param {string} prefix - Folder path prefix (empty for root)
     * @returns {Promise<Array>} - Array of file metadata objects
     */
    async list(prefix = "") {
      return this.withRetry(async () => {
        const path = prefix ? this.toDropboxPath(prefix) : "";
        const allEntries = [];

        if (this.auth) {
          const accessToken = await this.auth.getValidToken();
          this.client = new Dropbox.Dropbox({ accessToken, fetch });
        }

        this.logger.log(
          "info",
          `[DropboxService] Starting list for path: "${path}"`
        );

        let hasMore = true;
        let cursor = null;

        // First request
        const firstResult = await this.client.filesListFolder({
          path: path || "",
          recursive: true,
          include_deleted: false,
        });

        allEntries.push(...firstResult.result.entries);
        hasMore = firstResult.result.has_more;
        cursor = firstResult.result.cursor;

        this.logger.log(
          "info",
          `[DropboxService] First page: ${firstResult.result.entries.length} items, has_more: ${hasMore}`
        );

        // Continue with pagination if needed
        while (hasMore && cursor) {
          const continueResult = await this.client.filesListFolderContinue({
            cursor,
          });

          allEntries.push(...continueResult.result.entries);
          hasMore = continueResult.result.has_more;
          cursor = continueResult.result.cursor;

          this.logger.log(
            "info",
            `[DropboxService] Fetched page: ${continueResult.result.entries.length} items, total so far: ${allEntries.length}`
          );
        }

        this.logger.log(
          "success",
          `[DropboxService] List complete. Total files found: ${allEntries.length}`
        );

        // Convert to S3-compatible format for compatibility
        return allEntries
          .filter((entry) => entry[".tag"] === "file")
          .map((entry) => ({
            Key: entry.path_display.substring(1), // Remove leading /
            Size: entry.size,
            LastModified: entry.server_modified,
            path_display: entry.path_display,
            name: entry.name,
          }));
      });
    }

    /**
     * Download file with full response object
     * @param {string} key - File path
     * @returns {Promise<Object>} - Full download response
     */
    async downloadWithResponse(key) {
      return this.withRetry(async () => {
        const path = this.toDropboxPath(key);

        if (this.auth) {
          const accessToken = await this.auth.getValidToken();
          this.client = new Dropbox.Dropbox({ accessToken, fetch });
        }

        const result = await this.client.filesDownload({ path });
        return result.result;
      });
    }

    /**
     * Copy a file server-side (no download/upload)
     * @param {string} sourceKey - Source file path
     * @param {string} destinationKey - Destination file path
     * @returns {Promise<Object>} - Copy result
     */
    async copyObject(sourceKey, destinationKey) {
      return this.withRetry(async () => {
        const fromPath = this.toDropboxPath(sourceKey);
        const toPath = this.toDropboxPath(destinationKey);

        if (this.auth) {
          const accessToken = await this.auth.getValidToken();
          this.client = new Dropbox.Dropbox({ accessToken, fetch });
        }

        const result = await this.client.filesCopyV2({
          from_path: fromPath,
          to_path: toPath,
          autorename: false,
        });

        this.logger.log("success", `Copied ${sourceKey} → ${destinationKey}`);
        return result.result.metadata;
      });
    }

    /**
     * Batch copy multiple files server-side
     * Handles async job polling for large batches
     * @param {Array} entries - Array of {from_path, to_path} objects
     * @returns {Promise<Array>} - Array of copy results
     */
    async copyBatch(entries) {
      if (entries.length === 0) return [];

      // Convert entries to Dropbox format
      const dropboxEntries = entries.map((entry) => ({
        from_path: this.toDropboxPath(entry.from_path || entry.fromPath),
        to_path: this.toDropboxPath(entry.to_path || entry.toPath),
        autorename: false,
      }));

      this.logger.log(
        "info",
        `Starting batch copy of ${dropboxEntries.length} files`
      );

      if (this.auth) {
        const accessToken = await this.auth.getValidToken();
        this.client = new Dropbox.Dropbox({ accessToken, fetch });
      }

      // Start batch copy
      const batchResult = await this.client.filesCopyBatchV2({
        entries: dropboxEntries,
        autorename: false,
      });

      const resultTag = batchResult.result[".tag"];

      // If completed immediately
      if (resultTag === "complete") {
        this.logger.log(
          "success",
          `Batch copy completed immediately: ${entries.length} files`
        );
        return batchResult.result.entries;
      }

      // If async job started
      if (resultTag === "async_job_id") {
        const asyncJobId = batchResult.result.async_job_id;
        this.logger.log("info", `Batch copy started as async job: ${asyncJobId}`);

        // Poll for completion
        return await this.pollAsyncJob(asyncJobId, "copy");
      }

      throw new Error(`Unexpected batch copy result: ${resultTag}`);
    }

    /**
     * Poll an async job until completion
     * @param {string} asyncJobId - Async job ID
     * @param {string} operation - Operation type ('copy' or 'delete')
     * @returns {Promise<Array>} - Job results
     */
    async pollAsyncJob(asyncJobId, operation = "copy") {
      const maxAttempts = 60; // 5 minutes max (5s intervals)
      const pollInterval = 5000; // 5 seconds

      for (let attempt = 0; attempt < maxAttempts; attempt++) {
        await new Promise((resolve) => setTimeout(resolve, pollInterval));

        if (this.auth) {
          const accessToken = await this.auth.getValidToken();
          this.client = new Dropbox.Dropbox({ accessToken, fetch });
        }

        // Check job status
        const checkMethod =
          operation === "copy"
            ? this.client.filesCopyBatchCheckV2.bind(this.client)
            : this.client.filesDeleteBatchCheck.bind(this.client);

        const checkResult = await checkMethod({ async_job_id: asyncJobId });
        const status = checkResult.result[".tag"];

        this.logger.log("info", `Async job ${asyncJobId} status: ${status}`);

        if (status === "complete") {
          this.logger.log("success", `Async job ${asyncJobId} completed`);
          return checkResult.result.entries || [];
        }

        if (status === "failed") {
          throw new Error(
            `Async job ${asyncJobId} failed: ${JSON.stringify(checkResult.result)}`
          );
        }

        // Status is 'in_progress', continue polling
      }

      throw new Error(`Async job ${asyncJobId} timed out after ${maxAttempts} attempts`);
    }

    /**
     * Batch delete multiple files
     * @param {Array} entries - Array of {path} objects
     * @returns {Promise<Array>} - Array of delete results
     */
    async deleteBatch(entries) {
      if (entries.length === 0) return [];

      // Convert entries to Dropbox format
      const dropboxEntries = entries.map((entry) => ({
        path: this.toDropboxPath(entry.path || entry.Key),
      }));

      this.logger.log(
        "info",
        `Starting batch delete of ${dropboxEntries.length} files`
      );

      if (this.auth) {
        const accessToken = await this.auth.getValidToken();
        this.client = new Dropbox.Dropbox({ accessToken, fetch });
      }

      // Start batch delete
      const batchResult = await this.client.filesDeleteBatch({
        entries: dropboxEntries,
      });

      const resultTag = batchResult.result[".tag"];

      // If completed immediately
      if (resultTag === "complete") {
        this.logger.log(
          "success",
          `Batch delete completed immediately: ${entries.length} files`
        );
        return batchResult.result.entries;
      }

      // If async job started
      if (resultTag === "async_job_id") {
        const asyncJobId = batchResult.result.async_job_id;
        this.logger.log("info", `Batch delete started as async job: ${asyncJobId}`);

        // Poll for completion
        return await this.pollAsyncJob(asyncJobId, "delete");
      }

      throw new Error(`Unexpected batch delete result: ${resultTag}`);
    }
  }
  class SyncOrchestrator {
    constructor(
      configManager,
      dataService,
      s3Service,
      logger,
      operationQueue = null
    ) {
      this.config = configManager;
      this.dataService = dataService;
      this.s3Service = s3Service;
      this.logger = logger;
      this.operationQueue = operationQueue;
      this.metadata = this.loadMetadata();
      this.syncInProgress = false;
      this.autoSyncInterval = null;
      this.largeArrayKeys = ["TM_useUserCharacters"];
    }
    loadMetadata() {
      const stored = localStorage.getItem("tcs_local-metadata");
      const result = stored ? JSON.parse(stored) : { lastSync: 0, items: {} };
      return result;
    }
    saveMetadata() {
      localStorage.setItem("tcs_local-metadata", JSON.stringify(this.metadata));
    }
    getLastCloudSync() {
      const stored = localStorage.getItem("tcs_last-cloud-sync");
      return stored ? parseInt(stored) : 0;
    }
    setLastCloudSync(timestamp) {
      localStorage.setItem("tcs_last-cloud-sync", timestamp.toString());
    }
    getItemSize(data, key) {
      if (this.largeArrayKeys.includes(key) && Array.isArray(data)) {
        let totalSize = 2; // for '[' and ']'
        for (let i = 0; i < data.length; i++) {
          try {
            totalSize += JSON.stringify(data[i]).length;
            if (i < data.length - 1) {
              totalSize++; // for ','
            }
          } catch (e) {
            // Fallback for an item that can't be stringified
            this.logger.log(
              "warning",
              `Could not stringify element ${i} in large array ${key}`
            );
            totalSize += 100; // arbitrary small size
          }
        }
        return totalSize;
      }
      // Fallback to the old method for all other items
      return JSON.stringify(data).length;
    }

    /**
     * Detects changes between local storage and the last known sync state.
     * This uses a combined strategy:
     * - For CHAT items (key starts with 'CHAT_'): Uses the `updatedAt` timestamp for fast, memory-safe change detection.
     * - For all other items: Uses the original `size`-based comparison.
     * This prevents memory crashes caused by stringifying large chat objects.
     */
    async detectChanges() {
      const changedItems = [];
      const now = Date.now();
      const localItemKeys = await this.dataService.getAllItemKeys();

      // Use memory-efficient streaming for iterating through all local items
      const { totalSize } = await this.dataService.estimateDataSize();
      const itemsIterator = this.dataService.streamAllItemsInternal();

      for await (const batch of itemsIterator) {
        for (const item of batch) {
          const key = item.id;
          const value = item.data;
          const existingItem = this.metadata.items[key];

          // Skip items that are already marked for deletion in local metadata
          if (existingItem?.deleted) {
            continue;
          }

          let hasChanged = false;
          let changeReason = "unknown";
          let itemLastModified = now;
          let currentSize = 0;

          // ================== START: COMBINED DETECTION STRATEGY ==================

          // STRATEGY 1: Timestamp-based detection for CHAT items
          if (
            key.startsWith("CHAT_") &&
            item.type === "idb" &&
            value?.updatedAt
          ) {
            itemLastModified = value.updatedAt; // Use the timestamp from the object itself

            if (!existingItem) {
              hasChanged = true;
              changeReason = "new-chat";
            } else if (itemLastModified > (existingItem.lastModified || 0)) {
              hasChanged = true;
              changeReason = "timestamp";
            } else if (!existingItem.synced) {
              hasChanged = true;
              changeReason = "never-synced-chat";
            }
          }
          // STRATEGY 2: Size-based detection for all other items (the original, safe logic)
          else {
            currentSize = this.getItemSize(value, key);
            itemLastModified = existingItem?.lastModified || 0; // Preserve existing timestamp if any

            if (!existingItem) {
              hasChanged = true;
              changeReason = "new";
            } else if (currentSize !== existingItem.size) {
              hasChanged = true;
              changeReason = "size";
              itemLastModified = now; // Update timestamp on size change
            } else if (!existingItem.synced) {
              hasChanged = true;
              changeReason = "never-synced";
            }
          }

          if (hasChanged) {
            const change = {
              id: key,
              type: item.type,
              lastModified: itemLastModified,
              reason: changeReason,
            };
            // Only attach size if it was part of the detection logic
            if (currentSize > 0) {
              change.size = currentSize;
            }
            changedItems.push(change);
          }
          // =================== END: COMBINED DETECTION STRATEGY ===================
        }
      }

      for (const [itemId, metadata] of Object.entries(this.metadata.items)) {
        if (metadata.deleted && metadata.deleted > (metadata.synced || 0)) {
          if (
            !changedItems.some(
              (item) => item.id === itemId && item.reason === "tombstone"
            )
          ) {
            changedItems.push({
              id: itemId,
              type: metadata.type,
              deleted: metadata.deleted,
              tombstoneVersion: metadata.tombstoneVersion || 1,
              reason: "tombstone",
            });
          }
        }
      }

      // Find ghost items in metadata
      this.logger.log(
        "info",
        "🔍 Checking for items deleted locally by comparing metadata against actual keys..."
      );
      let newlyDeletedCount = 0;
      for (const itemId in this.metadata.items) {
        const metadataItem = this.metadata.items[itemId];

        if (!localItemKeys.has(itemId) && !metadataItem.deleted) {
          this.logger.log(
            "info",
            `⚰️ Detected locally deleted item: ${itemId}. Creating tombstone.`
          );

          changedItems.push({
            id: itemId,
            type: metadataItem.type || "idb",
            deleted: Date.now(),
            tombstoneVersion: (metadataItem.tombstoneVersion || 0) + 1,
            reason: "detected-deletion",
          });
          newlyDeletedCount++;
        }
      }
      if (newlyDeletedCount > 0) {
        this.logger.log(
          "success",
          `✅ Found ${newlyDeletedCount} newly deleted item(s) to be synced to the cloud.`
        );
      }

      return { changedItems, hasChanges: changedItems.length > 0 };
    }

    /**
     * Syncs detected changes up to the S3 cloud.
     * After uploading an item, it updates the local metadata:
     * - For CHAT items, it stores the `lastModified` timestamp.
     * - For other items, it stores the `size`.
     */
    async syncToCloud() {
      if (this.syncInProgress) {
        this.logger.log("skip", "Sync to cloud already in progress");
        return;
      }
      this.syncInProgress = true;
      try {
        const { changedItems } = await this.detectChanges();
        if (changedItems.length === 0) {
          this.logger.log("info", "No local items to sync to cloud");
          this.syncInProgress = false;
          return;
        }

        this.logger.log(
          "start",
          `Syncing ${changedItems.length} changed items to cloud...`
        );

        const cloudMetadata = await this.getCloudMetadata();
        let itemsSynced = 0;

        const uploadPromises = changedItems.map(async (item) => {
          // Conflict resolution: if cloud version is newer, skip upload
          const cloudItem = cloudMetadata.items[item.id];
          if (
            cloudItem &&
            !item.deleted &&
            (cloudItem.lastModified || 0) > (item.lastModified || 0)
          ) {
            this.logger.log(
              "skip",
              `Skipping upload for ${item.id}, cloud version is newer.`
            );
            this.metadata.items[item.id] = { ...cloudItem }; // Update local metadata to match cloud
            return;
          }

          try {
            // Handle TOMBSTONES (deletions)
            if (item.deleted || item.reason === "tombstone") {
              const timestamp = Date.now();
              const tombstoneData = {
                deleted: item.deleted || timestamp,
                type: item.type,
                tombstoneVersion: item.tombstoneVersion || 1,
                synced: timestamp,
              };
              this.metadata.items[item.id] = tombstoneData;
              cloudMetadata.items[item.id] = { ...tombstoneData };
              itemsSynced++;
              this.logger.log(
                "info",
                `🗑️ Synced tombstone for "${item.id}" to cloud.`
              );
            }
            // Handle regular item UPLOADS
            else {
              const data = await this.dataService.getItem(item.id, item.type);
              if (data) {
                await this.s3Service.upload(
                  `items/${item.id}.json`,
                  data,
                  false,
                  item.id
                );

                // ================== START: UPDATED METADATA SAVING ==================
                const newMetadataEntry = {
                  synced: Date.now(),
                  type: item.type,
                  lastModified: item.lastModified,
                };

                // For non-chat items, we must also store the size for future comparisons.
                if (!item.id.startsWith("CHAT_")) {
                  newMetadataEntry.size =
                    item.size || this.getItemSize(data, item.id);
                }

                this.metadata.items[item.id] = newMetadataEntry;
                cloudMetadata.items[item.id] = { ...newMetadataEntry };
                // =================== END: UPDATED METADATA SAVING ===================

                itemsSynced++;
                this.logger.log(
                  "info",
                  `Synced key "${item.id}" to cloud (reason: ${item.reason}).`
                );
              }
            }
          } catch (error) {
            this.logger.log(
              "error",
              `Failed to sync key "${item.id}": ${error.message}`
            );
            throw error;
          }
        });

        await Promise.allSettled(uploadPromises);

        if (itemsSynced > 0) {
          cloudMetadata.lastSync = Date.now();
          await this.s3Service.upload("metadata.json", cloudMetadata, true);
          this.metadata.lastSync = cloudMetadata.lastSync;
          this.setLastCloudSync(cloudMetadata.lastSync);
          this.saveMetadata();
          await this.updateSyncDiagnosticsCache();
          this.logger.log(
            "success",
            `Sync to cloud completed - ${itemsSynced} items processed.`
          );
        } else {
          this.logger.log(
            "info",
            "Sync to cloud finished, but no new items were uploaded."
          );
        }
      } catch (error) {
        this.logger.log(
          "error",
          "An error occurred during syncToCloud",
          error.message
        );
        throw error;
      } finally {
        this.syncInProgress = false;
      }
    }

    async retrySyncTombstone(item) {
      this.logger.log(
        "info",
        `🔄 Retrying tombstone sync for key "${item.id}"`
      );
      const cloudMetadata = await this.getCloudMetadata();
      const timestamp = Date.now();
      const tombstoneData = {
        deleted: item.deleted || timestamp,
        deletedAt: item.deleted || timestamp,
        type: item.type,
        tombstoneVersion: item.tombstoneVersion || 1,
        synced: timestamp,
      };
      this.metadata.items[item.id] = tombstoneData;
      cloudMetadata.items[item.id] = { ...tombstoneData };
      await this.s3Service.upload("metadata.json", cloudMetadata, true);
      this.saveMetadata();
      await this.updateSyncDiagnosticsCache();
      this.logger.log(
        "success",
        `✅ Retry tombstone sync completed for key "${item.id}"`
      );
    }
    async syncFromCloud() {
      if (this.syncInProgress) {
        this.logger.log("skip", "Sync from cloud already in progress");
        return;
      }
      this.syncInProgress = true;
      try {
        const { metadata: cloudMetadata, etag: cloudMetadataETag } =
          await this.getCloudMetadataWithETag();
        this.logger.log("info", "Downloaded cloud metadata", {
          ETag: cloudMetadataETag,
          lastSync: cloudMetadata.lastSync
            ? new Date(cloudMetadata.lastSync).toISOString()
            : "never",
        });
        const debugEnabled =
          new URLSearchParams(window.location.search).get("log") === "true";
        if (debugEnabled && cloudMetadata?.items) {
          const cloudItems = Object.keys(cloudMetadata.items);
          const cloudDeleted = cloudItems.filter(
            (id) => cloudMetadata.items[id].deleted
          ).length;
          const cloudActive = cloudItems.length - cloudDeleted;
          console.log(
            `📊 Cloud Metadata Stats: Total=${cloudItems.length}, Active=${cloudActive}, Deleted=${cloudDeleted}`
          );
        }
        const lastMetadataETag = localStorage.getItem("tcs_metadata_etag");
        const hasCloudChanges = cloudMetadataETag !== lastMetadataETag;
        const cloudLastSync = cloudMetadata.lastSync || 0;
        if (!hasCloudChanges) {
          this.logger.log(
            "info",
            "No cloud changes detected based on ETag - skipping item downloads"
          );
          this.metadata.lastSync = cloudLastSync;
          this.setLastCloudSync(cloudLastSync);
          this.saveMetadata();
          this.logger.log("success", "Sync from cloud completed (no changes)");
          return;
        }
        this.logger.log(
          "info",
          `Cloud changes detected - proceeding with full sync`
        );
        const itemsToDownload = Object.entries(cloudMetadata.items).filter(
          ([key, cloudItem]) => {
            if (this.config.shouldExclude(key)) {
              return false;
            }
            const localItem = this.metadata.items[key];
            const localTombstone =
              this.dataService.getTombstoneFromStorage(key);
            if (cloudItem.deleted) {
              const cloudVersion = cloudItem.tombstoneVersion || 1;
              const localMetadataVersion = localItem?.deleted
                ? localItem.tombstoneVersion || 1
                : 0;
              const localStorageVersion = localTombstone?.tombstoneVersion || 0;
              const localVersion = Math.max(
                localMetadataVersion,
                localStorageVersion
              );
              return cloudVersion > localVersion;
            }
            if (localItem?.deleted) {
              return (cloudItem.lastModified || 0) > localItem.deleted;
            }
            if (!localItem) {
              return true;
            }
            return (
              (cloudItem.lastModified || 0) >
              (localItem.lastModified || 0) + 2000
            );
          }
        );
        if (itemsToDownload.length > 0) {
          this.logger.log(
            "info",
            `Processing ${itemsToDownload.length} items from cloud`
          );
        }
        const downloadPromises = itemsToDownload.map(
          async ([key, cloudItem]) => {
            if (cloudItem.deleted) {
              this.logger.log(
                "info",
                `🗑️ Processing cloud tombstone for key "${key}" (v${
                  cloudItem.tombstoneVersion || 1
                })`
              );
              await this.dataService.performDelete(key, cloudItem.type);
              const tombstoneData = {
                deleted: cloudItem.deleted,
                deletedAt: cloudItem.deletedAt || cloudItem.deleted,
                type: cloudItem.type,
                tombstoneVersion: cloudItem.tombstoneVersion || 1,
              };
              this.dataService.saveTombstoneToStorage(key, tombstoneData);
              this.metadata.items[key] = { ...cloudItem };
              this.logger.log("info", `Synced key "${key}" from cloud`);
            } else {
              const data = await this.s3Service.download(`items/${key}.json`);
              if (data) {
                await this.dataService.saveItem(data, cloudItem.type, key);
                const syncTime = Date.now();
                this.metadata.items[key] = {
                  synced: syncTime,
                  type: cloudItem.type,
                  size: cloudItem.size || this.getItemSize(data),
                  lastModified: syncTime,
                };
                this.logger.log("info", `Synced key "${key}" from cloud`);
              }
            }
          }
        );
        await Promise.allSettled(downloadPromises);
        this.metadata.lastSync = cloudLastSync;
        this.setLastCloudSync(cloudLastSync);
        localStorage.setItem("tcs_metadata_etag", cloudMetadataETag);
        this.saveMetadata();
        await this.updateSyncDiagnosticsCache();
        this.logger.log("success", "Sync from cloud completed");
      } catch (error) {
        this.logger.log("error", "Failed to sync from cloud", error.message);
        throw error;
      } finally {
        this.syncInProgress = false;
      }
    }
    async createInitialSync() {
      this.logger.log("start", "Creating initial sync");
      try {
        const { changedItems } = await this.detectChanges();
        const cloudMetadata = {
          lastSync: Date.now(),
          items: {},
        };
        const uploadPromises = changedItems.map(async (item) => {
          if (item.deleted || item.reason === "tombstone") {
            const tombstoneData = {
              deleted: item.deleted || Date.now(),
              deletedAt: item.deleted || Date.now(),
              type: item.type,
              tombstoneVersion: item.tombstoneVersion || 1,
              synced: Date.now(),
            };
            this.metadata.items[item.id] = tombstoneData;
            cloudMetadata.items[item.id] = { ...tombstoneData };
            this.logger.log(
              "info",
              `🗑️ Added tombstone for ${item.id} to initial sync`
            );
          } else {
            const data = await this.dataService.getItem(item.id, item.type);
            if (data) {
              await this.s3Service.upload(`items/${item.id}.json`, data);
              this.metadata.items[item.id] = {
                synced: Date.now(),
                type: item.type,
                size: item.size || this.getItemSize(data),
                lastModified: item.lastModified,
              };
              cloudMetadata.items[item.id] = {
                ...this.metadata.items[item.id],
              };
            }
          }
        });
        await Promise.allSettled(uploadPromises);
        await this.s3Service.upload("metadata.json", cloudMetadata, true);
        this.metadata.lastSync = cloudMetadata.lastSync;
        this.setLastCloudSync(cloudMetadata.lastSync);
        this.saveMetadata();
        await this.updateSyncDiagnosticsCache();
        this.logger.log(
          "success",
          `Initial sync completed - ${changedItems.length} items uploaded`
        );
      } catch (error) {
        this.logger.log(
          "error",
          "Failed to create initial sync",
          error.message
        );
        throw error;
      }
    }
    async performFullSync() {
      await this.initializeLocalMetadata();
      const urlParams = new URLSearchParams(window.location.search);
      const debugEnabled =
        urlParams.get("log") === "true" || urlParams.has("log");
      if (debugEnabled) {
        const localItems = Object.keys(this.metadata.items || {});
        const localDeleted = localItems.filter(
          (id) => this.metadata.items[id].deleted
        ).length;
        const localActive = localItems.length - localDeleted;
        console.log(
          `📊 Local Metadata Stats: Total=${localItems.length}, Active=${localActive}, Deleted=${localDeleted}`
        );
      }
      await this.syncFromCloud();
      const cloudMetadata = await this.getCloudMetadata();
      const localMetadataEmpty =
        Object.keys(this.metadata.items || {}).length === 0;
      const cloudMetadataEmpty =
        Object.keys(cloudMetadata.items || {}).length === 0;
      if (localMetadataEmpty && cloudMetadataEmpty) {
        const { totalSize, itemCount } =
          await this.dataService.estimateDataSize();
        if (itemCount > 0) {
          this.logger.log(
            "info",
            `🚀 Fresh setup detected: ${itemCount} local items found with empty metadata. Triggering initial sync.`
          );
          await this.createInitialSync();
        } else {
          this.logger.log(
            "info",
            "Fresh setup with no local data - nothing to sync"
          );
        }
      } else {
        await this.syncToCloud();
      }
      const now = Date.now();
      const lastCleanup = localStorage.getItem("tcs_last-tombstone-cleanup");
      const cleanupInterval = 24 * 60 * 60 * 1000;
      if (!lastCleanup || now - parseInt(lastCleanup) > cleanupInterval) {
        this.logger.log("info", "🧹 Starting periodic tombstone cleanup");
        const localCleaned = await this.cleanupOldTombstones();
        const cloudCleaned = await this.cleanupCloudTombstones();
        localStorage.setItem("tcs_last-tombstone-cleanup", now.toString());
        if (localCleaned > 0 || cloudCleaned > 0) {
          this.logger.log(
            "success",
            `Tombstone cleanup completed: ${localCleaned} local, ${cloudCleaned} cloud`
          );
        }
      }
      await this.updateSyncDiagnosticsCache();
    }
    async initializeLocalMetadata() {
      const isEmptyMetadata =
        Object.keys(this.metadata.items || {}).length === 0;
      if (!isEmptyMetadata) {
        return;
      }
      this.logger.log(
        "start",
        "🔧 Initializing local metadata from database contents"
      );
      const { totalSize } = await this.dataService.estimateDataSize();
      const useStreaming = totalSize > this.dataService.memoryThreshold;
      const tombstones = this.dataService.getAllTombstones();
      let itemCount = 0;
      let tombstoneCount = 0;
      this.logger.log(
        "info",
        `Using memory-efficient metadata initialization (dataset: ${this.dataService.formatSize(
          totalSize
        )})`
      );

      for await (const batch of this.dataService.streamAllItemsInternal()) {
        for (const item of batch) {
          if (item.id && item.data) {
            const key = item.id;
            this.metadata.items[key] = {
              synced: 0,
              type: item.type,
              size: this.getItemSize(item.data),
              lastModified: 0,
            };
            itemCount++;
          }
        }
        if (itemCount % 1000 === 0) {
          this.logger.log(
            "info",
            `Processed ${itemCount} items for metadata initialization`
          );
          await new Promise((resolve) => setTimeout(resolve, 10));
        }
      }
      for (const [itemId, tombstone] of tombstones.entries()) {
        if (!this.metadata.items[itemId]) {
          this.metadata.items[itemId] = {
            deleted: tombstone.deleted,
            deletedAt: tombstone.deletedAt || tombstone.deleted,
            type: tombstone.type,
            tombstoneVersion: tombstone.tombstoneVersion || 1,
            synced: 0,
          };
          tombstoneCount++;
        }
      }
      if (itemCount > 0 || tombstoneCount > 0) {
        this.saveMetadata();
        await this.updateSyncDiagnosticsCache();
        this.logger.log(
          "success",
          `✅ Local metadata initialized: ${itemCount} items, ${tombstoneCount} tombstones`
        );
      } else {
        this.logger.log("info", "No local items found to initialize metadata");
      }
      if (this.config.isConfigured()) {
        try {
          this.logger.log(
            "info",
            "🔍 Checking cloud for missing items to restore"
          );
          const cloudMetadata = await this.getCloudMetadata();
          let restoredCount = 0;
          for (const [cloudItemId, cloudItem] of Object.entries(
            cloudMetadata.items || {}
          )) {
            if (!cloudItem.deleted && !this.metadata.items[cloudItemId]) {
              try {
                const data = await this.s3Service.download(
                  `items/${cloudItemId}.json`
                );
                if (data) {
                  await this.dataService.saveItem(
                    data,
                    cloudItem.type,
                    cloudItemId
                  );
                  const syncTime = Date.now();
                  this.metadata.items[cloudItemId] = {
                    synced: syncTime,
                    type: cloudItem.type,
                    size: cloudItem.size || this.getItemSize(data),
                    lastModified: syncTime,
                  };
                  restoredCount++;
                  this.logger.log(
                    "info",
                    `📥 Restored missing item: ${cloudItemId}`
                  );
                }
              } catch (error) {
                this.logger.log(
                  "warning",
                  `Failed to restore item ${cloudItemId}: ${error.message}`
                );
              }
            } else if (cloudItem.deleted && !this.metadata.items[cloudItemId]) {
              try {
                await this.dataService.performDelete(
                  cloudItemId,
                  cloudItem.type
                );
                const tombstoneData = {
                  deleted: cloudItem.deleted,
                  deletedAt: cloudItem.deletedAt || cloudItem.deleted,
                  type: cloudItem.type,
                  tombstoneVersion: cloudItem.tombstoneVersion || 1,
                  synced: Date.now(),
                };
                this.dataService.saveTombstoneToStorage(
                  cloudItemId,
                  tombstoneData
                );
                this.metadata.items[cloudItemId] = tombstoneData;
                restoredCount++;
                this.logger.log(
                  "info",
                  `🗑️ Applied missing tombstone: ${cloudItemId}`
                );
              } catch (error) {
                this.logger.log(
                  "warning",
                  `Failed to apply tombstone ${cloudItemId}: ${error.message}`
                );
              }
            }
          }
          if (restoredCount > 0) {
            this.saveMetadata();
            await this.updateSyncDiagnosticsCache();
            this.logger.log(
              "success",
              `🔄 Restored ${restoredCount} missing items and tombstones from cloud`
            );
          } else {
            this.logger.log(
              "info",
              "No missing items found in cloud to restore"
            );
          }
        } catch (error) {
          this.logger.log(
            "warning",
            "Could not check cloud for missing items",
            error.message
          );
        }
      }
    }
    async cleanupCloudTombstones() {
      try {
        const cloudMetadata = await this.getCloudMetadata();
        const now = Date.now();
        const tombstoneRetentionPeriod = 30 * 24 * 60 * 60 * 1000;
        let cleanupCount = 0;
        if (cloudMetadata?.items) {
          for (const [itemId, metadata] of Object.entries(
            cloudMetadata.items
          )) {
            if (
              metadata.deleted &&
              now - metadata.deleted > tombstoneRetentionPeriod
            ) {
              delete cloudMetadata.items[itemId];
              cleanupCount++;
            }
          }
          if (cleanupCount > 0) {
            await this.s3Service.upload("metadata.json", cloudMetadata, true);
            this.logger.log(
              "info",
              `🧹 Cleaned up ${cleanupCount} old cloud tombstones`
            );
          }
        }
        return cleanupCount;
      } catch (error) {
        this.logger.log(
          "error",
          "Error cleaning up cloud tombstones",
          error.message
        );
        return 0;
      }
    }
    startAutoSync() {
      if (this.autoSyncInterval) clearInterval(this.autoSyncInterval);
      const interval = Math.max(this.config.get("syncInterval") * 1000, 15000);
      this.autoSyncInterval = setInterval(async () => {
        if (
          this.config.isConfigured() &&
          !this.syncOrchestrator.syncInProgress
        ) {
          try {
            await this.backupService.checkAndPerformDailyBackup();
            await this.syncOrchestrator.performFullSync();
          } catch (error) {
            this.logger.log(
              "error",
              "Auto-sync/backup cycle failed",
              error.message
            );
          }
        }
      }, interval);
      this.logger.log("info", "Auto-sync and daily backup check started");
    }
    async cleanupOldTombstones() {
      const now = Date.now();
      const tombstoneRetentionPeriod = 30 * 24 * 60 * 60 * 1000;
      let cleanupCount = 0;
      for (let i = localStorage.length - 1; i >= 0; i--) {
        const key = localStorage.key(i);
        if (key?.startsWith("tcs_tombstone_")) {
          try {
            const tombstone = JSON.parse(localStorage.getItem(key));
            if (
              tombstone?.deleted &&
              now - tombstone.deleted > tombstoneRetentionPeriod
            ) {
              localStorage.removeItem(key);
              cleanupCount++;
            }
          } catch {
            localStorage.removeItem(key);
            cleanupCount++;
          }
        }
      }
      for (const [itemId, metadata] of Object.entries(this.metadata.items)) {
        if (
          metadata?.deleted &&
          now - metadata.deleted > tombstoneRetentionPeriod
        ) {
          delete this.metadata.items[itemId];
          cleanupCount++;
        }
      }
      if (cleanupCount > 0) {
        this.saveMetadata();
        await this.updateSyncDiagnosticsCache();
        this.logger.log("info", `🧹 Cleaned up ${cleanupCount} old tombstones`);
      }
      return cleanupCount;
    }
    async getCloudMetadataWithETag() {
      try {
        const result = await this.s3Service.downloadWithResponse(
          "metadata.json"
        );
        const metadata = JSON.parse(result.Body.toString());
        const etag = result.ETag;
        if (!metadata || typeof metadata !== "object") {
          return { metadata: { lastSync: 0, items: {} }, etag };
        }
        if (!metadata.items) {
          metadata.items = {};
        }
        return { metadata, etag };
      } catch (error) {
        if (error.code === "NoSuchKey" || error.statusCode === 404) {
          return { metadata: { lastSync: 0, items: {} }, etag: null };
        }
        throw error;
      }
    }
    async getCloudMetadata() {
      const { metadata } = await this.getCloudMetadataWithETag();
      return metadata;
    }
    async getSyncDiagnostics() {
      try {
        const { totalSize, itemCount } =
          await this.dataService.estimateDataSize();
        const localCount = itemCount;
        let chatItems = 0;
        for await (const batch of this.dataService.streamAllItemsInternal()) {
          for (const item of batch) {
            if (item.id.startsWith("CHAT_")) {
              chatItems++;
            }
          }
        }

        const metadataCount = Object.keys(this.metadata.items || {}).length;
        const metadataDeleted = Object.values(this.metadata.items || {}).filter(
          (item) => item.deleted
        ).length;
        const metadataActive = metadataCount - metadataDeleted;

        const cloudMetadata = await this.getCloudMetadata();
        const cloudCount = Object.keys(cloudMetadata.items || {}).length;
        const cloudDeleted = Object.values(cloudMetadata.items || {}).filter(
          (item) => item.deleted
        ).length;
        const cloudActive = cloudCount - cloudDeleted;
        const cloudChatItems = Object.keys(cloudMetadata.items || {}).filter(
          (id) => id.startsWith("CHAT_") && !cloudMetadata.items[id].deleted
        ).length;

        const hasIssues =
          localCount !== metadataActive ||
          metadataActive !== cloudActive ||
          chatItems !== cloudChatItems;

        const overallStatus = hasIssues ? "⚠️" : "✅";
        const lastUpdated = new Date().toLocaleTimeString();
        const summary = `Updated: ${lastUpdated}`;

        const details = [
          { type: "📱 Local Items", count: localCount },
          { type: "📋 Local Metadata", count: metadataActive },
          { type: "☁️ Cloud Metadata", count: cloudActive },
          { type: "💬 Chat Sync", count: `${chatItems} ⟷ ${cloudChatItems}` },
        ];

        const diagnosticsData = {
          timestamp: Date.now(),
          localItems: localCount,
          localMetadata: metadataActive,
          cloudMetadata: cloudActive,
          chatSyncLocal: chatItems,
          chatSyncCloud: cloudChatItems,
        };
        localStorage.setItem(
          "tcs_sync_diagnostics",
          JSON.stringify(diagnosticsData)
        );

        return { overallStatus, summary, details };
      } catch (error) {
        this.logger.log(
          "error",
          "Failed to get sync diagnostics",
          error.message
        );
        return {
          overallStatus: "❌",
          summary: "Error fetching diagnostics",
          details: [],
        };
      }
    }
    async updateSyncDiagnosticsCache() {
      try {
        const { totalSize, itemCount } =
          await this.dataService.estimateDataSize();
        const localCount = itemCount;
        let chatItems = 0;
        for await (const batch of this.dataService.streamAllItemsInternal()) {
          for (const item of batch) {
            if (item.id.startsWith("CHAT_")) {
              chatItems++;
            }
          }
        }
        const metadataCount = Object.keys(this.metadata.items || {}).length;
        const metadataDeleted = Object.values(this.metadata.items || {}).filter(
          (item) => item.deleted
        ).length;
        const metadataActive = metadataCount - metadataDeleted;
        const cloudMetadata = await this.getCloudMetadata();
        const cloudCount = Object.keys(cloudMetadata.items || {}).length;
        const cloudDeleted = Object.values(cloudMetadata.items || {}).filter(
          (item) => item.deleted
        ).length;
        const cloudActive = cloudCount - cloudDeleted;
        const cloudChatItems = Object.keys(cloudMetadata.items || {}).filter(
          (id) => id.startsWith("CHAT_") && !cloudMetadata.items[id].deleted
        ).length;
        const diagnosticsData = {
          timestamp: Date.now(),
          localItems: localCount,
          localMetadata: metadataActive,
          cloudMetadata: cloudActive,
          chatSyncLocal: chatItems,
          chatSyncCloud: cloudChatItems,
        };
        localStorage.setItem(
          "tcs_sync_diagnostics",
          JSON.stringify(diagnosticsData)
        );
        this.logger.log("info", "📊 Sync diagnostics cache updated", {
          localItems: diagnosticsData.localItems,
          cloudItems: diagnosticsData.cloudMetadata,
          chatSync: `${diagnosticsData.chatSyncLocal}/${diagnosticsData.chatSyncCloud}`,
          timestamp: new Date(diagnosticsData.timestamp).toLocaleTimeString(),
        });
      } catch (error) {
        this.logger.log(
          "warning",
          "Failed to update sync diagnostics cache",
          error.message
        );
      }
    }
    async loadSyncDiagnostics(modal) {
      const diagnosticsBody = modal.querySelector("#sync-diagnostics-body");
      if (!diagnosticsBody) return;
      const overallStatusEl = modal.querySelector("#sync-overall-status");
      const summaryEl = modal.querySelector("#sync-diagnostics-summary");
      const setContent = (html) => {
        diagnosticsBody.innerHTML = html;
      };

      if (!this.config.isConfigured()) {
        setContent(
          '<tr><td colspan="2" class="text-center py-2 text-zinc-500">Dropbox Not Configured</td></tr>'
        );
        if (overallStatusEl) overallStatusEl.textContent = "⚙️";
        if (summaryEl) summaryEl.textContent = "Setup required";
        return;
      }

      try {
        const diagnosticsData = localStorage.getItem("tcs_sync_diagnostics");
        if (!diagnosticsData) {
          setContent(
            '<tr><td colspan="2" class="text-center py-2 text-zinc-500">No diagnostics data available. Run a sync.</td></tr>'
          );
          if (overallStatusEl) overallStatusEl.textContent = "⚠️";
          if (summaryEl) summaryEl.textContent = "Waiting for first sync";
          return;
        }

        const data = JSON.parse(diagnosticsData);
        const rows = [
          {
            type: "📱 Local Items",
            count: data.localItems || 0,
          },
          {
            type: "📋 Local Metadata",
            count: data.localMetadata || 0,
          },
          {
            type: "☁️ Cloud Metadata",
            count: data.cloudMetadata || 0,
          },
          {
            type: "💬 Chat Sync",
            count: `${data.chatSyncLocal || 0} ⟷ ${data.chatSyncCloud || 0}`,
          },
        ];

        const tableHTML = rows
          .map(
            (row) => `
          <tr class="border-b border-zinc-700 hover:bg-zinc-700/30">
            <td class="py-1 px-2">${row.type}</td>
            <td class="text-right py-1 px-2">${row.count}</td>
          </tr>
        `
          )
          .join("");

        const hasIssues =
          data.localItems !== data.localMetadata ||
          data.localMetadata !== data.cloudMetadata ||
          data.chatSyncLocal !== data.chatSyncCloud;

        const overallStatus = hasIssues ? "⚠️" : "✅";
        const lastUpdated = new Date(data.timestamp || 0).toLocaleTimeString();
        const summaryText = `Updated: ${lastUpdated}`;

        if (overallStatusEl) overallStatusEl.textContent = overallStatus;
        if (summaryEl) summaryEl.textContent = summaryText;
        setContent(tableHTML);
      } catch (error) {
        console.error("Failed to load sync diagnostics:", error);
        setContent(
          '<tr><td colspan="2" class="text-center py-2 text-red-400">Error loading diagnostics from storage</td></tr>'
        );
        if (overallStatusEl) overallStatusEl.textContent = "❌";
        if (summaryEl) summaryEl.textContent = "Error";
      }
    }
    setupDiagnosticsToggle(modal) {
      const header = modal.querySelector("#sync-diagnostics-header");
      const content = modal.querySelector("#sync-diagnostics-content");
      const chevron = modal.querySelector("#sync-diagnostics-chevron");
      if (!header || !content || !chevron) return;
      const setVisibility = (expanded) => {
        if (expanded) {
          content.classList.remove("hidden");
          chevron.style.transform = "rotate(180deg)";
        } else {
          content.classList.add("hidden");
          chevron.style.transform = "rotate(0deg)";
        }
      };
      setVisibility(this.diagnosticsExpanded);
      const toggleDiagnostics = () => {
        this.diagnosticsExpanded = !this.diagnosticsExpanded;
        setVisibility(this.diagnosticsExpanded);
      };
      const clickHandler = toggleDiagnostics;
      const touchHandler = (e) => {
        e.preventDefault();
        toggleDiagnostics();
      };
      header.addEventListener("click", clickHandler);
      header.addEventListener("touchend", touchHandler);
      this.modalCleanupCallbacks.push(() => {
        if (header) {
          header.removeEventListener("click", clickHandler);
          header.removeEventListener("touchend", touchHandler);
        }
      });
    }
    setupDiagnosticsRefresh(modal) {
      const refreshButton = modal.querySelector("#sync-diagnostics-refresh");
      if (!refreshButton) return;
      const refreshHandler = (e) => {
        e.stopPropagation();
        this.loadSyncDiagnostics(modal);
        refreshButton.style.transform = "rotate(360deg)";
        setTimeout(() => {
          refreshButton.style.transform = "rotate(0deg)";
        }, 300);
      };
      refreshButton.addEventListener("click", refreshHandler);
      this.modalCleanupCallbacks.push(() => {
        if (refreshButton) {
          refreshButton.removeEventListener("click", refreshHandler);
        }
      });
    }
    cleanup() {
      if (this.autoSyncInterval) {
        clearInterval(this.autoSyncInterval);
        this.autoSyncInterval = null;
      }
      this.syncInProgress = false;
      this.config = null;
      this.dataService = null;
      this.s3Service = null;
      this.logger = null;
      this.operationQueue = null;
      this.metadata = null;
    }
  }
  class BackupService {
    constructor(dataService, s3Service, logger) {
      this.dataService = dataService;
      this.s3Service = s3Service;
      this.logger = logger;
    }

    async createSnapshot(name) {
      this.logger.log("start", `Creating server-side snapshot: ${name}`);
      try {
        await this.ensureSyncIsCurrent();
        return await this.createServerSideSnapshot(name);
      } catch (error) {
        this.logger.log(
          "error",
          "Server-side snapshot creation failed",
          error.message
        );
        throw error;
      }
    }

    async checkAndPerformDailyBackup() {
      const lastBackupStr = localStorage.getItem("tcs_last-daily-backup");
      const now = new Date();
      const currentDateStr = `${now.getFullYear()}${String(
        now.getMonth() + 1
      ).padStart(2, "0")}${String(now.getDate()).padStart(2, "0")}`;
      if (!lastBackupStr || lastBackupStr !== currentDateStr) {
        this.logger.log("info", "Starting daily backup...");
        await this.performDailyBackup();
        localStorage.setItem("tcs_last-daily-backup", currentDateStr);
        this.logger.log("success", "Daily backup completed");
        return true;
      }
      return false;
    }

    async performDailyBackup() {
      this.logger.log("info", "Starting server-side daily backup");
      try {
        await this.ensureSyncIsCurrent();
        return await this.createServerSideDailyBackup();
      } catch (error) {
        this.logger.log(
          "error",
          "Server-side daily backup failed",
          error.message
        );
        throw error;
      }
    }

    async ensureSyncIsCurrent() {
      this.logger.log("info", "Ensuring sync is current before backup");
      const orchestrator = window.cloudSyncApp?.syncOrchestrator;
      if (orchestrator && !orchestrator.syncInProgress) {
        try {
          await orchestrator.performFullSync();
          this.logger.log("success", "Sync completed before backup");
        } catch (error) {
          this.logger.log(
            "warning",
            `Pre-backup sync failed: ${error.message}, proceeding with backup anyway`
          );
        }
      } else {
        this.logger.log(
          "info",
          "Sync already in progress or not available, proceeding with backup"
        );
      }
    }

    async createServerSideSnapshot(name) {
      this.logger.log(
        "info",
        "Creating server-side snapshot using Dropbox copy operations"
      );
      const timestamp = new Date()
        .toISOString()
        .replace(/[-:]/g, "")
        .replace(/\..+/, "");
      const backupFolder = `backups/s-${name.replace(
        /[^a-zA-Z0-9]/g,
        "-"
      )}-${timestamp}`;

      try {
        const itemsList = await this.s3Service.list("items/");
        this.logger.log(
          "info",
          `Found ${itemsList.length} items to backup via server-side copy`
        );

        let copiedItems = 0;
        const concurrency = 20;
        const itemsToProcess = itemsList.filter(
          (item) => item.Key && item.Key.startsWith("items/")
        );

        for (let i = 0; i < itemsToProcess.length; i += concurrency) {
          const batch = itemsToProcess.slice(i, i + concurrency);
          const copyPromises = batch.map(async (item) => {
            try {
              const destinationKey = `${backupFolder}/${item.Key}`;
              await this.s3Service.copyObject(item.Key, destinationKey);
              return { success: true, key: item.Key };
            } catch (copyError) {
              this.logger.log(
                "warning",
                `Failed to copy item ${item.Key}: ${copyError.message}`
              );
              return {
                success: false,
                key: item.Key,
                error: copyError.message,
              };
            }
          });

          const batchResults = await Promise.allSettled(copyPromises);
          const successfulCopies = batchResults.filter(
            (result) => result.status === "fulfilled" && result.value?.success
          ).length;
          copiedItems += successfulCopies;

          if (
            copiedItems % 200 === 0 ||
            i + concurrency >= itemsToProcess.length
          ) {
            this.logger.log(
              "info",
              `Server-side copied ${copiedItems}/${itemsToProcess.length} items`
            );
          }
        }

        try {
          const metadataDestination = `${backupFolder}/metadata.json`;
          await this.s3Service.copyObject("metadata.json", metadataDestination);
          this.logger.log(
            "info",
            "Server-side copied metadata.json to snapshot"
          );
        } catch (metadataError) {
          this.logger.log(
            "warning",
            `Failed to copy metadata: ${metadataError.message}`
          );
        }

        const manifest = {
          type: "server-side-snapshot",
          name: name,
          created: Date.now(),
          totalItems: itemsToProcess.length,
          copiedItems: copiedItems,
          format: "server-side",
          version: "3.0",
          backupFolder: backupFolder,
        };

        await this.s3Service.upload(
          `${backupFolder}/backup-manifest.json`,
          manifest,
          true
        );

        this.logger.log(
          "success",
          `Server-side snapshot created: ${backupFolder} (${copiedItems} items copied)`
        );
        return true;
      } catch (error) {
        this.logger.log(
          "error",
          `Server-side snapshot failed: ${error.message}`
        );
        throw error;
      }
    }

    async createServerSideDailyBackup() {
      this.logger.log(
        "info",
        "Creating server-side daily backup using Dropbox copy operations"
      );
      const today = new Date();
      const dateString = `${today.getFullYear()}${String(
        today.getMonth() + 1
      ).padStart(2, "0")}${String(today.getDate()).padStart(2, "0")}`;
      const backupFolder = `backups/typingmind-backup-${dateString}`;

      try {
        const itemsList = await this.s3Service.list("items/");
        this.logger.log(
          "info",
          `Found ${itemsList.length} items for server-side daily backup`
        );

        let copiedItems = 0;
        const concurrency = 20;
        const itemsToProcess = itemsList.filter(
          (item) => item.Key && item.Key.startsWith("items/")
        );

        for (let i = 0; i < itemsToProcess.length; i += concurrency) {
          const batch = itemsToProcess.slice(i, i + concurrency);
          const copyPromises = batch.map(async (item) => {
            try {
              const destinationKey = `${backupFolder}/${item.Key}`;
              await this.s3Service.copyObject(item.Key, destinationKey);
              return { success: true, key: item.Key };
            } catch (copyError) {
              this.logger.log(
                "warning",
                `Failed to copy item ${item.Key}: ${copyError.message}`
              );
              return {
                success: false,
                key: item.Key,
                error: copyError.message,
              };
            }
          });

          const batchResults = await Promise.allSettled(copyPromises);
          const successfulCopies = batchResults.filter(
            (result) => result.status === "fulfilled" && result.value?.success
          ).length;
          copiedItems += successfulCopies;

          if (
            copiedItems % 200 === 0 ||
            i + concurrency >= itemsToProcess.length
          ) {
            this.logger.log(
              "info",
              `Daily backup: server-side copied ${copiedItems}/${itemsToProcess.length} items`
            );
          }
        }

        try {
          const metadataDestination = `${backupFolder}/metadata.json`;
          await this.s3Service.copyObject("metadata.json", metadataDestination);
          this.logger.log(
            "info",
            "Server-side copied metadata.json to daily backup"
          );
        } catch (metadataError) {
          this.logger.log(
            "warning",
            `Failed to copy metadata to daily backup: ${metadataError.message}`
          );
        }

        const manifest = {
          type: "server-side-daily-backup",
          name: "daily-auto",
          created: Date.now(),
          totalItems: itemsToProcess.length,
          copiedItems: copiedItems,
          format: "server-side",
          version: "3.0",
          backupFolder: backupFolder,
        };

        await this.s3Service.upload(
          `${backupFolder}/backup-manifest.json`,
          manifest,
          true
        );

        this.logger.log(
          "success",
          `Server-side daily backup created: ${backupFolder} (${copiedItems} items copied)`
        );
        await this.cleanupOldBackups();
        return true;
      } catch (error) {
        this.logger.log(
          "error",
          `Server-side daily backup failed: ${error.message}`
        );
        throw error;
      }
    }

    formatFileSize(bytes) {
      if (bytes === 0) return "0 B";
      const k = 1024;
      const sizes = ["B", "KB", "MB", "GB"];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    }

    async loadBackupList() {
      try {
        const objects = await this.s3Service.list("backups/");
        const backups = [];

        for (const obj of objects) {
          if (obj.Key.endsWith("/backup-manifest.json")) {
            try {
              const manifest = await this.s3Service.download(obj.Key, true);
              if (manifest.format === "server-side") {
                const backupFolder =
                  manifest.backupFolder ||
                  obj.Key.replace("/backup-manifest.json", "");
                const backupName = backupFolder.replace("backups/", "");
                const backupType = this.getBackupType(backupName);

                backups.push({
                  key: obj.Key,
                  name: backupName,
                  displayName: backupName,
                  modified: obj.LastModified,
                  format: "server-side",
                  totalItems: manifest.totalItems,
                  copiedItems: manifest.copiedItems,
                  type: backupType,
                  backupFolder: backupFolder,
                  sortOrder: backupType === "snapshot" ? 1 : 2,
                });
              }
            } catch (error) {
              this.logger.log(
                "warning",
                `Failed to read server-side manifest for ${obj.Key}`
              );
            }
          }
        }

        return backups.sort((a, b) => {
          if (a.sortOrder !== b.sortOrder) {
            return a.sortOrder - b.sortOrder;
          }
          return new Date(b.modified) - new Date(a.modified);
        });
      } catch (error) {
        this.logger.log("error", "Failed to load backup list", error.message);
        return [];
      }
    }

    getBackupType(filename) {
      if (filename.startsWith("s-")) {
        return "snapshot";
      } else if (filename.startsWith("typingmind-backup-")) {
        return "daily";
      }
      return "unknown";
    }

    async restoreFromBackup(key) {
      this.logger.log("start", `Restoring from backup: ${key}`);
      try {
        if (key.endsWith("/backup-manifest.json")) {
          return await this.restoreFromServerSideBackup(key);
        } else {
          this.logger.log(
            "error",
            "Invalid or unsupported backup format selected for restore."
          );
          throw new Error("Unsupported backup format");
        }
      } catch (error) {
        this.logger.log("error", "Backup restoration failed", error.message);
        throw error;
      }
    }

    async restoreFromServerSideBackup(manifestKey) {
      this.logger.log("info", "Restoring from server-side backup format");

      try {
        const manifest = await this.s3Service.download(manifestKey, true);
        if (!manifest || manifest.format !== "server-side") {
          throw new Error("Invalid server-side backup manifest");
        }

        const backupFolder = manifest.backupFolder;
        this.logger.log(
          "info",
          `Restoring server-side backup: ${manifest.name} (${manifest.totalItems} items)`
        );

        const backupFiles = await this.s3Service.list(backupFolder + "/");
        const itemFiles = backupFiles.filter(
          (file) =>
            file.Key.startsWith(backupFolder + "/items/") &&
            file.Key.endsWith(".json")
        );

        this.logger.log(
          "info",
          `Found ${itemFiles.length} items to restore via server-side copy`
        );

        this.logger.log(
          "warning",
          "⚠️ CRITICAL: This will overwrite ALL cloud data."
        );

        let restoredCount = 0;
        const concurrency = 20;

        for (let i = 0; i < itemFiles.length; i += concurrency) {
          const batch = itemFiles.slice(i, i + concurrency);
          const copyPromises = batch.map(async (file) => {
            try {
              const itemFilename = file.Key.replace(backupFolder + "/", "");
              await this.s3Service.copyObject(file.Key, itemFilename);
              return { success: true, key: file.Key };
            } catch (copyError) {
              this.logger.log(
                "warning",
                `Failed to restore item ${file.Key}: ${copyError.message}`
              );
              return {
                success: false,
                key: file.Key,
                error: copyError.message,
              };
            }
          });

          const batchResults = await Promise.allSettled(copyPromises);
          const successfulRestores = batchResults.filter(
            (result) => result.status === "fulfilled" && result.value?.success
          ).length;
          restoredCount += successfulRestores;

          if (
            restoredCount % 200 === 0 ||
            i + concurrency >= itemFiles.length
          ) {
            this.logger.log(
              "info",
              `Server-side restored ${restoredCount}/${itemFiles.length} items`
            );
          }
        }

        const metadataFile = backupFiles.find(
          (file) => file.Key === backupFolder + "/metadata.json"
        );
        if (metadataFile) {
          try {
            await this.s3Service.copyObject(metadataFile.Key, "metadata.json");
            this.logger.log("info", "Server-side restored metadata.json");
          } catch (metadataError) {
            this.logger.log(
              "warning",
              `Failed to restore metadata: ${metadataError.message}`
            );
          }
        }

        localStorage.removeItem("tcs_local-metadata");
        localStorage.removeItem("tcs_last-cloud-sync");
        localStorage.removeItem("tcs_metadata_etag");

        this.logger.log(
          "success",
          `Server-side backup restore completed: ${restoredCount} items restored via Dropbox copy`
        );
        this.logger.log(
          "success",
          "Page will reload in 3 seconds to sync restored data."
        );

        setTimeout(() => {
          window.location.reload();
        }, 3000);

        return true;
      } catch (error) {
        this.logger.log(
          "error",
          `Server-side backup restore failed: ${error.message}`
        );
        throw error;
      }
    }

    async cleanupOldBackups() {
      try {
        const objects = await this.s3Service.list("backups/");
        const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000;
        let deletedBackups = 0;

        const serverSideManifests = objects.filter((obj) =>
          obj.Key.endsWith("/backup-manifest.json")
        );

        for (const manifestObj of serverSideManifests) {
          const isOldBackup =
            new Date(manifestObj.LastModified).getTime() < thirtyDaysAgo;
          if (isOldBackup) {
            try {
              const manifest = await this.s3Service.download(
                manifestObj.Key,
                true
              );
              if (manifest?.format === "server-side") {
                const backupFolder = manifest.backupFolder;

                const backupFiles = objects.filter((obj) =>
                  obj.Key.startsWith(backupFolder + "/")
                );
                for (const file of backupFiles) {
                  try {
                    await this.s3Service.delete(file.Key);
                  } catch (fileError) {
                    this.logger.log(
                      "warning",
                      `Failed to delete server-side backup file: ${file.Key}`
                    );
                  }
                }
                deletedBackups++;
                this.logger.log(
                  "info",
                  `Cleaned up server-side backup: ${backupFolder}`
                );
              }
            } catch (error) {
              this.logger.log(
                "warning",
                `Failed to cleanup server-side backup: ${manifestObj.Key}`
              );
            }
          }
        }

        if (deletedBackups > 0) {
          this.logger.log(
            "success",
            `Cleaned up ${deletedBackups} old backups`
          );
        }
      } catch (error) {
        this.logger.log(
          "error",
          "Failed to cleanup old backups",
          error.message
        );
      }
    }
  }
  class OperationQueue {
    constructor(logger) {
      this.logger = logger;
      this.queue = new Map();
      this.processing = false;
      this.maxRetries = 3;
      this.activeTimeouts = new Set();
      this.maxQueueSize = 100;
      this.lastCleanup = 0;
    }
    add(operationId, operation, priority = "normal") {
      const now = Date.now();
      if (now - this.lastCleanup > 10 * 60 * 1000) {
        this.cleanupStaleOperations(now);
        this.lastCleanup = now;
      }
      if (this.queue.has(operationId)) {
        this.logger.log("skip", `Operation ${operationId} already queued`);
        return;
      }
      if (this.queue.size >= this.maxQueueSize) {
        this.logger.log(
          "warning",
          `Queue full (${this.maxQueueSize}), removing oldest operation`
        );
        const oldestKey = this.queue.keys().next().value;
        this.queue.delete(oldestKey);
      }
      this.queue.set(operationId, {
        id: operationId,
        operation,
        priority,
        retries: 0,
        addedAt: now,
      });
      this.logger.log("info", `📋 Queued operation: ${operationId}`);
      this.process();
    }
    cleanupStaleOperations(now) {
      const staleThreshold = 60 * 60 * 1000;
      let removedCount = 0;
      for (const [operationId, operation] of this.queue.entries()) {
        if (
          now - operation.addedAt > staleThreshold &&
          operation.retries >= this.maxRetries
        ) {
          this.queue.delete(operationId);
          removedCount++;
        }
      }
      if (removedCount > 0) {
        this.logger.log(
          "info",
          `🧹 Cleaned up ${removedCount} stale operations from queue`
        );
      }
    }
    async process() {
      if (this.processing || this.queue.size === 0) return;
      this.processing = true;
      while (this.queue.size > 0) {
        const operations = Array.from(this.queue.values());
        const highPriority = operations.filter((op) => op.priority === "high");
        const nextOp =
          highPriority.length > 0 ? highPriority[0] : operations[0];
        try {
          this.logger.log("info", `⚡ Executing: ${nextOp.id}`);
          await nextOp.operation();
          this.queue.delete(nextOp.id);
          this.logger.log("success", `✅ Completed: ${nextOp.id}`);
        } catch (error) {
          this.logger.log("error", `❌ Failed: ${nextOp.id}`, error.message);
          if (nextOp.retries < this.maxRetries) {
            nextOp.retries++;
            const delay = Math.min(1000 * Math.pow(2, nextOp.retries), 10000);
            this.logger.log(
              "warning",
              `🔄 Retrying ${nextOp.id} in ${delay}ms (${nextOp.retries}/${this.maxRetries})`
            );
            const timeoutId = setTimeout(() => {
              this.activeTimeouts.delete(timeoutId);
              if (this.queue.has(nextOp.id)) {
                this.process();
              }
            }, delay);
            this.activeTimeouts.add(timeoutId);
            break;
          } else {
            this.logger.log("error", `💀 Giving up on: ${nextOp.id}`);
            this.queue.delete(nextOp.id);
          }
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      this.processing = false;
    }
    clear() {
      this.queue.clear();
      this.clearTimeouts();
      this.processing = false;
    }
    clearTimeouts() {
      for (const timeoutId of this.activeTimeouts) {
        clearTimeout(timeoutId);
      }
      this.activeTimeouts.clear();
    }
    size() {
      return this.queue.size;
    }
    cleanup() {
      this.logger?.log("info", "🧹 OperationQueue cleanup starting");
      try {
        this.clear();
        this.lastCleanup = 0;
        this.maxRetries = 0;
        this.maxQueueSize = 0;
        this.logger?.log("success", "✅ OperationQueue cleanup completed");
        this.logger = null;
      } catch (error) {
        console.warn("OperationQueue cleanup error:", error);
      }
    }
  }
  class LeaderElection {
    constructor(channelName, logger) {
      this.channelName = channelName;
      this.logger = logger;
      this.tabId = `tab_${Date.now()}_${Math.random()
        .toString(36)
        .substring(2, 9)}`;
      this.leaderId = null;
      this.isLeader = false;
      this.channel = null;
      this.heartbeatInterval = null;
      this.electionTimeout = null;
      this.leaderTimeout = null;
      this.onBecameLeaderCallback = () => {};
      this.onBecameFollowerCallback = () => {};
      this.HEARTBEAT_INTERVAL = 5000;
      this.FAST_LEADER_TIMEOUT = 12000;
      this.SLOW_LEADER_TIMEOUT = 70000;
      this.ELECTION_TIMEOUT = 100;
      this.visibilityChangeHandler = this.handleVisibilityChange.bind(this);
      try {
        if ("BroadcastChannel" in window) {
          this.channel = new BroadcastChannel(this.channelName);
          this.channel.onmessage = this.handleMessage.bind(this);
          document.addEventListener(
            "visibilitychange",
            this.visibilityChangeHandler
          );
        } else {
          this.logger.log(
            "warning",
            "BroadcastChannel not supported. Multi-tab sync will not be safe."
          );
          this.becomeLeader();
        }
      } catch (error) {
        this.logger.log(
          "error",
          "Failed to create BroadcastChannel.",
          error.message
        );
      }
    }
    elect() {
      if (!this.channel) {
        this.becomeLeader();
        return;
      }
      this.logger.log(
        "info",
        `[LeaderElection] Tab ${this.tabId} starting election.`
      );
      this.clearElectionTimeout();
      this.postMessage({ type: "request-leader" });
      this.electionTimeout = setTimeout(() => {
        this.logger.log(
          "info",
          `[LeaderElection] No leader responded within ${this.ELECTION_TIMEOUT}ms.`
        );
        this.becomeLeader();
      }, this.ELECTION_TIMEOUT);
    }
    handleVisibilityChange() {
      if (document.visibilityState === "visible" && this.isLeader) {
        this.logger.log(
          "info",
          `[LeaderElection] Tab ${this.tabId} became visible and believes it's the leader. Re-running election to confirm.`
        );
        this.elect();
      }

      if (this.isLeader) {
        this.postMessage({
          type: "ping",
          id: this.tabId,
          visibilityState: document.visibilityState,
        });
      }
    }
    becomeLeader() {
      this.logger.log(
        "info",
        `[LeaderElection] 👑 Tab ${this.tabId} is now the LEADER.`
      );
      this.isLeader = true;
      this.leaderId = this.tabId;
      this.clearElectionTimeout();
      this.clearLeaderTimeout();
      if (this.channel) {
        this.postMessage({ type: "iam-leader", id: this.tabId });
        if (this.heartbeatInterval) clearInterval(this.heartbeatInterval);
        this.heartbeatInterval = setInterval(() => {
          this.postMessage({
            type: "ping",
            id: this.tabId,
            visibilityState: document.visibilityState,
          });
        }, this.HEARTBEAT_INTERVAL);
      }
      this.onBecameLeaderCallback();
    }
    becomeFollower(leaderId) {
      if (this.isLeader) {
        this.logger.log(
          "info",
          `[LeaderElection] 🚶‍♀️ Tab ${this.tabId} is now a FOLLOWER.`
        );
      }
      this.isLeader = false;
      this.leaderId = leaderId;
      this.clearElectionTimeout();
      if (this.heartbeatInterval) {
        clearInterval(this.heartbeatInterval);
        this.heartbeatInterval = null;
      }
      this.resetLeaderTimeout();
      this.onBecameFollowerCallback();
    }
    handleMessage(event) {
      const msg = event.data;
      if (!msg || !msg.type) return;
      switch (msg.type) {
        case "request-leader":
          if (this.isLeader) {
            this.postMessage({ type: "pong", id: this.tabId });
          }
          break;
        case "iam-leader":
          if (msg.id !== this.tabId) {
            this.becomeFollower(msg.id);
          }
          break;
        case "leader-unloading":
          if (msg.id === this.leaderId) {
            this.logger.log(
              "info",
              `[LeaderElection] Leader ${msg.id} is unloading. Starting new election immediately.`
            );
            this.leaderId = null;
            this.elect();
          }
          break;
        case "pong":
          if (msg.id !== this.tabId) {
            this.becomeFollower(msg.id);
          }
          break;
        case "ping":
          if (msg.id !== this.tabId && msg.id === this.leaderId) {
            this.resetLeaderTimeout(msg.visibilityState);
          }
          break;
      }
    }
    resetLeaderTimeout(leaderVisibilityState = "visible") {
      this.clearLeaderTimeout();
      const timeout =
        leaderVisibilityState === "visible"
          ? this.FAST_LEADER_TIMEOUT
          : this.SLOW_LEADER_TIMEOUT;
      this.leaderTimeout = setTimeout(() => {
        this.logger.log(
          "warning",
          `[LeaderElection] Leader ${this.leaderId} timed out (state: ${leaderVisibilityState}). Starting new election.`
        );
        this.leaderId = null;
        this.elect();
      }, timeout);
    }
    clearElectionTimeout() {
      if (this.electionTimeout) {
        clearTimeout(this.electionTimeout);
        this.electionTimeout = null;
      }
    }
    clearLeaderTimeout() {
      if (this.leaderTimeout) {
        clearTimeout(this.leaderTimeout);
        this.leaderTimeout = null;
      }
    }
    postMessage(msg) {
      try {
        this.channel?.postMessage(msg);
      } catch (error) {
        this.logger.log(
          "error",
          "[LeaderElection] Failed to post message.",
          error.message
        );
      }
    }
    onBecameLeader(callback) {
      this.onBecameLeaderCallback = callback;
    }
    onBecameFollower(callback) {
      this.onBecameFollowerCallback = callback;
    }
    cleanup() {
      this.logger.log("info", "[LeaderElection] Cleaning up.");
      if (this.isLeader) {
        this.postMessage({ type: "leader-unloading", id: this.tabId });
      }
      if (this.channel) {
        this.channel.close();
        this.channel = null;
      }
      document.removeEventListener(
        "visibilitychange",
        this.visibilityChangeHandler
      );
      if (this.heartbeatInterval) clearInterval(this.heartbeatInterval);
      this.clearElectionTimeout();
      this.clearLeaderTimeout();
    }
  }
  class CloudSyncApp {
    constructor() {
      this.logger = new Logger();
      this.config = new ConfigManager();
      this.operationQueue = new OperationQueue(this.logger);
      this.dataService = new DataService(
        this.config,
        this.logger,
        this.operationQueue
      );
      this.cryptoService = new CryptoService(this.config, this.logger);

      // Initialize DropboxAuth for OAuth management
      this.dropboxAuth = new DropboxAuth(this.config, this.logger);

      // Initialize DropboxService (replaces S3Service)
      this.dropboxService = new DropboxService(
        this.config,
        this.cryptoService,
        this.logger,
        this.dropboxAuth
      );

      // Keep backward-compatible reference as s3Service
      // This allows existing code to work without changes
      this.s3Service = this.dropboxService;

      this.syncOrchestrator = new SyncOrchestrator(
        this.config,
        this.dataService,
        this.s3Service,
        this.logger,
        this.operationQueue
      );
      this.backupService = new BackupService(
        this.dataService,
        this.s3Service,
        this.logger
      );
      this.autoSyncInterval = null;
      this.eventListeners = [];
      this.modalCleanupCallbacks = [];
      this.noSyncMode = false;
      this.diagnosticsExpanded = false;
      this.leaderElection = null;
    }
    async initialize() {
      this.logger.log("start", "Initializing TypingMind Cloud Sync with Dropbox v1");

      // Check if we're being redirected back from Dropbox OAuth
      const authCode = this.dropboxAuth.checkForAuthCode();
      if (authCode) {
        try {
          this.logger.log("info", "Processing OAuth authorization code...");
          const tokens = await this.dropboxAuth.exchangeCodeForToken(authCode);

          // Store tokens
          this.config.set("accessToken", tokens.accessToken);
          this.config.set("refreshToken", tokens.refreshToken);
          this.config.set("tokenExpiry", Date.now() + tokens.expiresIn * 1000);
          this.config.save();

          this.logger.log("success", "OAuth authentication successful!");

          // Clean up URL
          const url = new URL(window.location);
          url.searchParams.delete("code");
          url.searchParams.delete("state");
          window.history.replaceState({}, "", url);
        } catch (error) {
          this.logger.log("error", "OAuth token exchange failed", error.message);
        }
      }

      this.leaderElection = new LeaderElection(
        "tcs-leader-election",
        this.logger
      );
      this.leaderElection.onBecameLeader(() => {
        this.logger.log(
          "info",
          "👑 This tab is now the leader. Starting background tasks."
        );
        this.runLeaderTasks();
      });
      this.leaderElection.onBecameFollower(() => {
        this.logger.log(
          "info",
          "🚶‍♀️ This tab is now a follower. Stopping background tasks."
        );
        if (this.autoSyncInterval) {
          clearInterval(this.autoSyncInterval);
          this.autoSyncInterval = null;
        }
      });
      const urlParams = new URLSearchParams(window.location.search);
      this.noSyncMode =
        urlParams.get("nosync") === "true" || urlParams.has("nosync");
      try {
        const { totalSize, itemCount } =
          await this.dataService.estimateDataSize();
        const useStreaming = totalSize > this.dataService.memoryThreshold;
        this.logger.log(
          "info",
          `Dataset size: ${this.dataService.formatSize(
            totalSize
          )} (${itemCount} items)${
            useStreaming ? " - Memory-efficient mode enabled" : ""
          }`
        );
      } catch (error) {
        this.logger.log(
          "warning",
          "Could not estimate dataset size",
          error.message
        );
      }
      const urlConfig = this.getConfigFromUrlParams();
      if (urlConfig.hasParams) {
        Object.keys(urlConfig.config).forEach((key) => {
          if (key === "exclusions") {
            localStorage.setItem(
              "tcs_sync-exclusions",
              urlConfig.config.exclusions
            );
            this.config.reloadExclusions();
          } else {
            this.config.set(key, urlConfig.config[key]);
          }
        });
        this.config.save();
        this.logger.log(
          "info",
          "Applied and saved URL parameters to config and localStorage."
        );
        this.removeConfigFromUrl();
      }
      if (this.noSyncMode) {
        this.logger.log(
          "info",
          "🚫 NoSync mode enabled - only snapshot functionality available"
        );
      }
      if (!this.noSyncMode && !this.checkMandatoryConfig(urlConfig.config)) {
        alert(
          "⚠️ Cloud Sync Configuration Required\n\nPlease configure the following mandatory fields in the sync settings:\n• Dropbox App Key\n• Encryption Key\n\nThen authenticate with Dropbox using OAuth.\n\nClick on the Sync button to open settings, then reload the page after configuration."
        );
        await this.waitForDOM();
        this.insertSyncButton();
        return;
      }
      await this.waitForDOM();
      this.insertSyncButton();
      if (urlConfig.autoOpen || urlConfig.hasParams) {
        this.logger.log(
          "info",
          "Auto-opening sync modal due to URL parameters"
        );
        setTimeout(() => this.openSyncModal(), 1000);
      }
      if (!this.noSyncMode) {
        if (this.config.isConfigured()) {
          try {
            await this.s3Service.initialize();
            this.leaderElection.elect();
          } catch (error) {
            this.logger.log("error", "Initialization failed", error.message);
            this.updateSyncStatus("error");
          }
        } else {
          this.logger.log(
            "info",
            "Dropbox not configured - running in limited capacity"
          );
        }
      } else {
        this.logger.log(
          "info",
          "NoSync mode: Daily backups and auto-sync disabled"
        );
        if (this.config.isConfigured()) {
          try {
            await this.s3Service.initialize();
          } catch (error) {
            this.logger.log("error", "Dropbox initialization failed", error.message);
          }
        }
      }
    }
    checkMandatoryConfig(urlConfig = {}) {
      const requiredFields = [
        { key: "tcs_dropbox_appkey", urlKey: "appKey" },
        { key: "tcs_encryptionkey", urlKey: "encryptionKey" },
      ];
      const missingFields = [];
      for (const field of requiredFields) {
        const localValue = localStorage.getItem(field.key);
        const urlValue = urlConfig[field.urlKey];
        if (
          (!localValue || localValue.trim() === "") &&
          (!urlValue || urlValue.trim() === "")
        ) {
          this.logger.log(
            "warning",
            `Missing mandatory field: ${field.key} (not in localStorage or URL params)`
          );
          missingFields.push(field.key);
        }
      }
      if (missingFields.length > 0) {
        this.logger.log(
          "warning",
          `Missing ${missingFields.length} mandatory fields`,
          missingFields
        );
        return false;
      }
      return true;
    }
    isSnapshotAvailable() {
      const urlConfig = this.getConfigFromUrlParams();
      return this.checkMandatoryConfig(urlConfig.config);
    }
    getConfigFromUrlParams() {
      const urlParams = new URLSearchParams(window.location.search);
      const config = {};
      const autoOpen = urlParams.has("config") || urlParams.has("autoconfig");
      const paramMap = {
        appkey: "appKey",
        accesstoken: "accessToken",
        refreshtoken: "refreshToken",
        encryptionkey: "encryptionKey",
        syncinterval: "syncInterval",
        exclusions: "exclusions",
      };
      let hasConfigParams = false;
      for (const [urlParam, configKey] of Object.entries(paramMap)) {
        const value = urlParams.get(urlParam);
        if (value !== null) {
          config[configKey] = value;
          hasConfigParams = true;
        }
      }
      const sensitiveKeys = {
        accesstoken: "accessToken",
        refreshtoken: "refreshToken",
        encryptionkey: "encryptionKey",
      };
      const rawQuery = window.location.search.substring(1);
      if (rawQuery) {
        const params = rawQuery.split("&");
        for (const p of params) {
          const idx = p.indexOf("=");
          if (idx > 0) {
            const key = p.substring(0, idx);
            if (sensitiveKeys[key]) {
              const value = decodeURIComponent(p.substring(idx + 1));
              config[sensitiveKeys[key]] = value;
              hasConfigParams = true;
            }
          }
        }
      }
      return {
        config: config,
        hasParams: hasConfigParams,
        autoOpen: autoOpen,
      };
    }
    removeConfigFromUrl() {
      const url = new URL(window.location);
      const params = url.searchParams;
      const paramsToRemove = [
        "appkey",
        "accesstoken",
        "refreshtoken",
        "encryptionkey",
        "syncinterval",
        "exclusions",
        "config",
        "autoconfig",
      ];
      let removedSomething = false;
      paramsToRemove.forEach((p) => {
        if (params.has(p)) {
          params.delete(p);
          removedSomething = true;
        }
      });
      if (removedSomething) {
        window.history.replaceState({}, document.title, url.toString());
        this.logger.log("info", "Removed configuration parameters from URL.");
      }
    }
    async waitForDOM() {
      if (document.readyState === "loading") {
        return new Promise((resolve) =>
          document.addEventListener("DOMContentLoaded", resolve)
        );
      }
    }
    insertSyncButton() {
      if (document.querySelector('[data-element-id="workspace-tab-cloudsync"]'))
        return;
      const style = document.createElement("style");
      style.textContent = `#sync-status-dot { position: absolute; top: 2px; width: 8px; height: 8px; border-radius: 50%; background-color: #6b7280; display: none; z-index: 10; }`;
      document.head.appendChild(style);
      const button = document.createElement("button");
      button.setAttribute("data-element-id", "workspace-tab-cloudsync");
      button.className =
        "min-w-[58px] sm:min-w-0 sm:aspect-auto aspect-square cursor-default h-12 md:h-[50px] flex-col justify-start items-start inline-flex focus:outline-0 focus:text-white w-full relative";
      button.innerHTML = `<span class="text-white/70 hover:bg-white/20 self-stretch h-12 md:h-[50px] px-0.5 py-1.5 rounded-xl flex-col justify-start items-center gap-1.5 flex transition-colors"><div class="relative"><svg class="w-5 h-5" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 18 18"><g fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M9 4.5A4.5 4.5 0 0114.5 9M9 13.5A4.5 4.5 0 013.5 9"/><polyline points="9,2.5 9,4.5 11,4.5"/><polyline points="9,15.5 9,13.5 7,13.5"/></g></svg><div id="sync-status-dot"></div></div><span class="font-normal self-stretch text-center text-xs leading-4 md:leading-none">Sync</span></span>`;
      button.addEventListener("click", () => this.openSyncModal());
      const chatButton = document.querySelector(
        'button[data-element-id="workspace-tab-chat"]'
      );
      if (chatButton?.parentNode) {
        chatButton.parentNode.insertBefore(button, chatButton.nextSibling);
      }
    }
    updateSyncStatus(status = "success") {
      const dot = document.getElementById("sync-status-dot");
      if (!dot) return;
      const colors = {
        success: "#22c55e",
        error: "#ef4444",
        warning: "#eab308",
        syncing: "#3b82f6",
      };
      dot.style.backgroundColor = colors[status] || "#6b7280";
      dot.style.display = "block";
    }
    openSyncModal() {
      if (document.querySelector(".cloud-sync-modal")) return;
      this.logger.log("start", "Opening sync modal");
      this.createModal();
    }
    createModal() {
      const overlay = document.createElement("div");
      overlay.className = "modal-overlay";
      overlay.style.cssText = `position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 9999;`;
      const modal = document.createElement("div");
      modal.className = "cloud-sync-modal";
      modal.innerHTML = this.getModalHTML();
      overlay.appendChild(modal);
      document.body.appendChild(overlay);
      this.setupModalEventListeners(modal, overlay);
    }
    getModalHTML() {
      const modeStatus = this.noSyncMode
        ? `<div class="mb-3 p-2 bg-orange-600 rounded-lg border border-orange-500">
             <div class="text-center text-sm font-medium">
               🚫 NoSync Mode Active - Only snapshot functionality available
             </div>
           </div>`
        : "";
      return `<div class="text-white text-left text-sm">
        <div class="flex justify-center items-center mb-3">
          <h3 class="text-center text-xl font-bold text-white">Dropbox Backup & Sync Settings</h3>
        </div>
        ${modeStatus}
        <div class="space-y-3">
          <div class="mt-4 bg-zinc-800 px-3 py-2 rounded-lg border border-zinc-700">
            <div class="flex items-center justify-between mb-2 cursor-pointer select-none" id="sync-diagnostics-header">
              <div class="flex items-center gap-2">
                <label class="block text-sm font-medium text-zinc-300">Sync Diagnostics</label>
                <span id="sync-overall-status" class="text-lg">✅</span>
                <button id="sync-diagnostics-refresh" class="text-zinc-400 hover:text-white transition-colors p-1 rounded" title="Refresh diagnostics">
                  <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                  </svg>
                </button>
              </div>
              <div class="flex items-center gap-1">
                <span id="sync-diagnostics-summary" class="text-xs text-zinc-400">Tap to view details</span>
                <svg id="sync-diagnostics-chevron" class="w-4 h-4 text-zinc-400 transform transition-transform duration-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                </svg>
              </div>
            </div>
            <div id="sync-diagnostics-content" class="overflow-x-auto">
              <table id="sync-diagnostics-table" class="w-full text-xs text-zinc-300 border-collapse">
                <thead>
                  <tr class="border-b border-zinc-600">
                    <th class="text-left py-1 px-2 font-medium">Type</th>
                    <th class="text-right py-1 px-2 font-medium">Count</th>
                  </tr>
                </thead>
                <tbody id="sync-diagnostics-body">
                  <tr><td colspan="2" class="text-center py-2 text-zinc-500">Loading...</td></tr>
                </tbody>
              </table>
            </div>
          </div>
          <div class="mt-4 bg-zinc-800 px-3 py-2 rounded-lg border border-zinc-700">
            <div class="flex items-center justify-between mb-1">
              <label class="block text-sm font-medium text-zinc-300">Available Backups</label>
            </div>
            <div class="space-y-2">
              <div class="w-full">
                <select id="backup-files" class="w-full px-2 py-1.5 border border-zinc-600 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm dark:bg-zinc-700 text-white">
                  <option value="">Please configure Dropbox credentials first</option>
                </select>
              </div>
              <div class="flex justify-end space-x-2">
                <button id="restore-backup-btn" class="z-1 px-2 py-1.5 text-sm text-white bg-green-600 rounded-md hover:bg-green-700 disabled:bg-gray-500 disabled:cursor-not-allowed" disabled>
                  Restore
                </button>
                <button id="delete-backup-btn" class="z-1 px-2 py-1.5 text-sm text-white bg-red-600 rounded-md hover:bg-red-700 disabled:bg-gray-500 disabled:cursor-not-allowed" disabled>
                  Delete
                </button>
              </div>
            </div>
          </div>
          <div class="mt-4 bg-zinc-800 px-3 py-2 rounded-lg border border-zinc-700">
            <div class="space-y-2">
              <div>
                <label for="dropbox-app-key" class="block text-sm font-medium text-zinc-300">Dropbox App Key <span class="text-red-400">*</span></label>
                <input id="dropbox-app-key" name="dropbox-app-key" type="text" value="${
                  this.config.get("appKey") || ""
                }" class="z-1 w-full px-2 py-1.5 border border-zinc-600 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm dark:bg-zinc-700 text-white" autocomplete="off" required>
                <p class="mt-1 text-xs text-zinc-400">Create an app at <a href="https://www.dropbox.com/developers/apps" target="_blank" class="text-blue-400 hover:text-blue-300">dropbox.com/developers/apps</a></p>
              </div>
              <div>
                <label class="block text-sm font-medium text-zinc-300 mb-2">Authentication Status</label>
                <div id="auth-status" class="flex items-center justify-between px-3 py-2 bg-zinc-700 rounded-md">
                  <span class="text-sm ${
                    this.config.get("accessToken") ? "text-green-400" : "text-yellow-400"
                  }">
                    ${
                      this.config.get("accessToken")
                        ? "✓ Authenticated"
                        : "⚠ Not authenticated"
                    }
                  </span>
                  <button id="authenticate-dropbox" class="px-3 py-1 text-sm text-white bg-blue-600 rounded-md hover:bg-blue-700 focus:outline-none">
                    ${this.config.get("accessToken") ? "Re-authenticate" : "Authenticate"}
                  </button>
                </div>
              </div>
              <div class="flex space-x-4">
                <div class="w-1/2">
                  <label for="sync-interval" class="block text-sm font-medium text-zinc-300">Sync Interval</label>
                  <input id="sync-interval" name="sync-interval" type="number" min="15" value="${this.config.get(
                    "syncInterval"
                  )}" class="z-1 w-full px-2 py-1.5 border border-zinc-600 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm dark:bg-zinc-700 text-white" autocomplete="off" required>
                </div>
                <div class="w-1/2">
                  <label for="encryption-key" class="block text-sm font-medium text-zinc-300">Encryption Key <span class="text-red-400">*</span></label>
                  <input id="encryption-key" name="encryption-key" type="password" value="${
                    this.config.get("encryptionKey") || ""
                  }" class="z-1 w-full px-2 py-1.5 border border-zinc-600 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm dark:bg-zinc-700 text-white" autocomplete="off" required>
                </div>
              </div>
              <div>
                <label for="sync-exclusions" class="block text-sm font-medium text-zinc-300">Exclusions (Comma separated)</label>
                <input id="sync-exclusions" name="sync-exclusions" type="text" value="${
                  localStorage.getItem("tcs_sync-exclusions") || ""
                }" class="z-1 w-full px-2 py-1.5 border border-zinc-600 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm dark:bg-zinc-700 text-white" placeholder="e.g., my-setting, another-setting" autocomplete="off">
              </div>
            </div>
          </div>
          <div class="flex items-center justify-end mb-4 space-x-2">
            <span class="text-sm text-zinc-400">Console Logging</span>
            <input type="checkbox" id="console-logging-toggle" class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded cursor-pointer">
          </div>
          <div class="flex justify-between space-x-2 mt-4">
            <button id="save-settings" class="z-1 inline-flex items-center px-3 py-1.5 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:bg-gray-500 disabled:cursor-default transition-colors">
              Save
            </button>
            <div class="flex space-x-2">
              <button id="sync-now" class="z-1 inline-flex items-center px-2 py-1 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 disabled:bg-gray-500 disabled:cursor-default transition-colors" ${
                this.noSyncMode ? "disabled" : ""
              }>
                ${this.noSyncMode ? "Sync Disabled" : "Sync Now"}
              </button>
              <button id="create-snapshot" class="z-1 inline-flex items-center px-2 py-1 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:bg-gray-500 disabled:cursor-default transition-colors" ${
                !this.isSnapshotAvailable() ? "disabled" : ""
              }>
                Snapshot
              </button>
              <button id="close-modal" class="z-1 inline-flex items-center px-2 py-1 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                Close
              </button>
            </div>
          </div>
          <div class="text-center mt-4">
            <span id="last-sync-msg" class="text-zinc-400">${
              this.noSyncMode
                ? "NoSync Mode: Automatic sync operations disabled"
                : ""
            }</span>
          </div>
          <div id="action-msg" class="text-center text-zinc-400"></div>
        </div>
      </div>`;
    }
    setupModalEventListeners(modal, overlay) {
      const closeModalHandler = () => this.closeModal(overlay);
      const saveSettingsHandler = () => this.saveSettings(overlay);
      const createSnapshotHandler = () => this.createSnapshot();
      const handleSyncNowHandler = () => this.handleSyncNow(modal);
      const consoleLoggingHandler = (e) =>
        this.logger.setEnabled(e.target.checked);
      const authenticateDropboxHandler = () => this.authenticateDropbox();
      overlay.addEventListener("click", closeModalHandler);
      modal.addEventListener("click", (e) => e.stopPropagation());
      modal
        .querySelector("#close-modal")
        .addEventListener("click", closeModalHandler);
      modal
        .querySelector("#save-settings")
        .addEventListener("click", saveSettingsHandler);
      modal
        .querySelector("#create-snapshot")
        .addEventListener("click", createSnapshotHandler);
      modal
        .querySelector("#sync-now")
        .addEventListener("click", handleSyncNowHandler);
      modal
        .querySelector("#console-logging-toggle")
        .addEventListener("change", consoleLoggingHandler);
      modal
        .querySelector("#authenticate-dropbox")
        .addEventListener("click", authenticateDropboxHandler);
      this.modalCleanupCallbacks.push(() => {
        overlay.removeEventListener("click", closeModalHandler);
        modal
          .querySelector("#close-modal")
          ?.removeEventListener("click", closeModalHandler);
        modal
          .querySelector("#save-settings")
          ?.removeEventListener("click", saveSettingsHandler);
        modal
          .querySelector("#create-snapshot")
          ?.removeEventListener("click", createSnapshotHandler);
        modal
          .querySelector("#sync-now")
          ?.removeEventListener("click", handleSyncNowHandler);
        modal
          .querySelector("#console-logging-toggle")
          ?.removeEventListener("change", consoleLoggingHandler);
        modal
          .querySelector("#authenticate-dropbox")
          ?.removeEventListener("click", authenticateDropboxHandler);
      });
      const consoleLoggingCheckbox = modal.querySelector(
        "#console-logging-toggle"
      );
      consoleLoggingCheckbox.checked = this.logger.enabled;
      this.populateFormFromUrlParams(modal);
      this.loadBackupList(modal);
      this.setupBackupListHandlers(modal);
      this.loadSyncDiagnostics(modal);
      this.setupDiagnosticsToggle(modal);
      this.setupDiagnosticsRefresh(modal);
    }
    populateFormFromUrlParams(modal) {
      const urlConfig = this.getConfigFromUrlParams();
      if (!urlConfig.hasParams) {
        this.logger.log("info", "No URL config parameters to populate");
        return;
      }
      this.logger.log(
        "info",
        "Populating form with URL parameters",
        urlConfig.config
      );
      const fieldMap = {
        appKey: "dropbox-app-key",
        encryptionKey: "encryption-key",
        syncInterval: "sync-interval",
        exclusions: "sync-exclusions",
      };
      let populatedCount = 0;
      for (const [configKey, fieldId] of Object.entries(fieldMap)) {
        const value = urlConfig.config[configKey];
        if (value !== undefined) {
          const field = modal.querySelector(`#${fieldId}`);
          if (field) {
            field.value = value;
            populatedCount++;
            this.logger.log(
              "info",
              `Populated field ${fieldId} with URL value`
            );
          }
        }
      }
      if (populatedCount > 0) {
        const actionMsg = modal.querySelector("#action-msg");
        if (actionMsg) {
          actionMsg.textContent = `✨ Auto-populated ${populatedCount} field(s) from URL parameters`;
          actionMsg.style.color = "#22c55e";
          setTimeout(() => {
            actionMsg.textContent = "";
            actionMsg.style.color = "";
          }, 5000);
        }
      }
    }
    handleSyncNow(modal) {
      if (this.noSyncMode) {
        alert(
          "⚠️ Sync operations are disabled in NoSync mode.\n\nTo enable sync operations, remove the ?nosync parameter from the URL and reload the page."
        );
        return;
      }
      const syncNowButton = modal.querySelector("#sync-now");
      const originalText = syncNowButton.textContent;
      syncNowButton.disabled = true;
      syncNowButton.textContent = "Working...";
      this.operationQueue.add(
        "manual-full-sync",
        async () => {
          await this.syncOrchestrator.performFullSync();
        },
        "high"
      );
      setTimeout(() => {
        syncNowButton.textContent = "Done!";
        setTimeout(() => {
          syncNowButton.textContent = originalText;
          syncNowButton.disabled = false;
        }, 2000);
      }, 1000);
    }
    async loadBackupList(modal) {
      try {
        const backupList = modal.querySelector("#backup-files");
        if (!backupList) return;
        backupList.innerHTML = '<option value="">Loading backups...</option>';
        backupList.disabled = true;
        if (!this.config.isConfigured()) {
          backupList.innerHTML =
            '<option value="">Please configure AWS credentials first</option>';
          backupList.disabled = false;
          return;
        }
        const backups = await this.backupService.loadBackupList();
        backupList.innerHTML = "";
        backupList.disabled = false;
        if (backups.length === 0) {
          const option = document.createElement("option");
          option.value = "";
          option.text = "No backups found";
          backupList.appendChild(option);
        } else {
          backups.forEach((backup) => {
            const option = document.createElement("option");
            option.value = backup.key;
            const total = backup.totalItems ?? "N/A";
            const copied = backup.copiedItems ?? total;
            const suffix = `(${copied}/${total})`;
            let prefix = "";
            if (backup.type === "snapshot") {
              prefix = "📸 ";
            } else if (backup.type === "daily") {
              prefix = "🗓️ ";
            }
            option.text = `${prefix}${
              backup.displayName || backup.name
            } ${suffix}`;
            backupList.appendChild(option);
          });
        }
        this.updateBackupButtonStates(modal);
        backupList.addEventListener("change", () =>
          this.updateBackupButtonStates(modal)
        );
      } catch (error) {
        console.error("Failed to load backup list:", error);
        if (backupList) {
          backupList.innerHTML =
            '<option value="">Error loading backups</option>';
          backupList.disabled = false;
        }
      }
    }
    updateBackupButtonStates(modal) {
      const backupList = modal.querySelector("#backup-files");
      const selectedValue = backupList.value || "";
      const restoreButton = modal.querySelector("#restore-backup-btn");
      const deleteButton = modal.querySelector("#delete-backup-btn");
      const isSnapshot = selectedValue.includes("s-");
      const isDailyBackup = selectedValue.includes("typingmind-backup-");
      const isChunkedBackup = selectedValue.endsWith("-metadata.json");
      const isMetadataFile = selectedValue === "metadata.json";
      const isItemsFile = selectedValue.startsWith("items/");
      if (restoreButton) {
        const canRestore =
          selectedValue && (isSnapshot || isDailyBackup || isChunkedBackup);
        restoreButton.disabled = !canRestore;
      }
      if (deleteButton) {
        const isProtectedFile = !selectedValue || isMetadataFile || isItemsFile;
        deleteButton.disabled = isProtectedFile;
      }
    }
    setupBackupListHandlers(modal) {
      const restoreButton = modal.querySelector("#restore-backup-btn");
      const deleteButton = modal.querySelector("#delete-backup-btn");
      const backupList = modal.querySelector("#backup-files");
      if (restoreButton) {
        restoreButton.addEventListener("click", async () => {
          const key = backupList.value;
          if (!key) {
            alert("Please select a backup to restore");
            return;
          }
          if (
            confirm(
              "Are you sure you want to restore this backup? This will overwrite your current data."
            )
          ) {
            try {
              restoreButton.disabled = true;
              restoreButton.textContent = "Restoring...";
              const success = await this.backupService.restoreFromBackup(
                key,
                this.cryptoService
              );
              if (success) {
                alert("Backup restored successfully! Page will reload.");
                location.reload();
              }
            } catch (error) {
              console.error("Failed to restore backup:", error);
              alert("Failed to restore backup: " + error.message);
              restoreButton.textContent = "Failed";
              setTimeout(() => {
                restoreButton.textContent = "Restore";
                restoreButton.disabled = false;
                this.updateBackupButtonStates(modal);
              }, 2000);
            }
          }
        });
      }
      if (deleteButton) {
        deleteButton.addEventListener("click", async () => {
          const key = backupList.value;
          if (!key) {
            alert("Please select a backup to delete");
            return;
          }
          if (
            confirm(
              "Are you sure you want to delete this backup? This cannot be undone."
            )
          ) {
            try {
              deleteButton.disabled = true;
              deleteButton.textContent = "Deleting...";
              await this.deleteBackupWithChunks(key);
              await this.loadBackupList(modal);
              deleteButton.textContent = "Deleted!";
              setTimeout(() => {
                deleteButton.textContent = "Delete";
                this.updateBackupButtonStates(modal);
              }, 2000);
            } catch (error) {
              console.error("Failed to delete backup:", error);
              alert("Failed to delete backup: " + error.message);
              deleteButton.textContent = "Failed";
              setTimeout(() => {
                deleteButton.textContent = "Delete";
                deleteButton.disabled = false;
                this.updateBackupButtonStates(modal);
              }, 2000);
            }
          }
        });
      }
    }
    async loadSyncDiagnostics(modal) {
      const diagnosticsBody = modal.querySelector("#sync-diagnostics-body");
      if (!diagnosticsBody) return;
      const overallStatusEl = modal.querySelector("#sync-overall-status");
      const summaryEl = modal.querySelector("#sync-diagnostics-summary");
      const setContent = (html) => {
        diagnosticsBody.innerHTML = html;
      };

      if (!this.config.isConfigured()) {
        setContent(
          '<tr><td colspan="2" class="text-center py-2 text-zinc-500">Dropbox Not Configured</td></tr>'
        );
        if (overallStatusEl) overallStatusEl.textContent = "⚙️";
        if (summaryEl) summaryEl.textContent = "Setup required";
        return;
      }

      try {
        const diagnosticsData = localStorage.getItem("tcs_sync_diagnostics");
        if (!diagnosticsData) {
          setContent(
            '<tr><td colspan="2" class="text-center py-2 text-zinc-500">No diagnostics data available. Run a sync.</td></tr>'
          );
          if (overallStatusEl) overallStatusEl.textContent = "⚠️";
          if (summaryEl) summaryEl.textContent = "Waiting for first sync";
          return;
        }

        const data = JSON.parse(diagnosticsData);
        const rows = [
          {
            type: "📱 Local Items",
            count: data.localItems || 0,
          },
          {
            type: "📋 Local Metadata",
            count: data.localMetadata || 0,
          },
          {
            type: "☁️ Cloud Metadata",
            count: data.cloudMetadata || 0,
          },
          {
            type: "💬 Chat Sync",
            count: `${data.chatSyncLocal || 0} ⟷ ${data.chatSyncCloud || 0}`,
          },
        ];

        const tableHTML = rows
          .map(
            (row) => `
          <tr class="border-b border-zinc-700 hover:bg-zinc-700/30">
            <td class="py-1 px-2">${row.type}</td>
            <td class="text-right py-1 px-2">${row.count}</td>
          </tr>
        `
          )
          .join("");

        const hasIssues =
          data.localItems !== data.localMetadata ||
          data.localMetadata !== data.cloudMetadata ||
          data.chatSyncLocal !== data.chatSyncCloud;

        const overallStatus = hasIssues ? "⚠️" : "✅";
        const lastUpdated = new Date(data.timestamp || 0).toLocaleTimeString();
        const summaryText = `Updated: ${lastUpdated}`;

        if (overallStatusEl) overallStatusEl.textContent = overallStatus;
        if (summaryEl) summaryEl.textContent = summaryText;
        setContent(tableHTML);
      } catch (error) {
        console.error("Failed to load sync diagnostics:", error);
        setContent(
          '<tr><td colspan="2" class="text-center py-2 text-red-400">Error loading diagnostics from storage</td></tr>'
        );
        if (overallStatusEl) overallStatusEl.textContent = "❌";
        if (summaryEl) summaryEl.textContent = "Error";
      }
    }
    setupDiagnosticsToggle(modal) {
      const header = modal.querySelector("#sync-diagnostics-header");
      const content = modal.querySelector("#sync-diagnostics-content");
      const chevron = modal.querySelector("#sync-diagnostics-chevron");
      if (!header || !content || !chevron) return;
      const setVisibility = (expanded) => {
        if (expanded) {
          content.classList.remove("hidden");
          chevron.style.transform = "rotate(180deg)";
        } else {
          content.classList.add("hidden");
          chevron.style.transform = "rotate(0deg)";
        }
      };
      setVisibility(this.diagnosticsExpanded);
      const toggleDiagnostics = () => {
        this.diagnosticsExpanded = !this.diagnosticsExpanded;
        setVisibility(this.diagnosticsExpanded);
      };
      const clickHandler = toggleDiagnostics;
      const touchHandler = (e) => {
        e.preventDefault();
        toggleDiagnostics();
      };
      header.addEventListener("click", clickHandler);
      header.addEventListener("touchend", touchHandler);
      this.modalCleanupCallbacks.push(() => {
        if (header) {
          header.removeEventListener("click", clickHandler);
          header.removeEventListener("touchend", touchHandler);
        }
      });
    }
    setupDiagnosticsRefresh(modal) {
      const refreshButton = modal.querySelector("#sync-diagnostics-refresh");
      if (!refreshButton) return;
      const refreshHandler = (e) => {
        e.stopPropagation();
        this.loadSyncDiagnostics(modal);
        refreshButton.style.transform = "rotate(360deg)";
        setTimeout(() => {
          refreshButton.style.transform = "rotate(0deg)";
        }, 300);
      };
      refreshButton.addEventListener("click", refreshHandler);
      this.modalCleanupCallbacks.push(() => {
        if (refreshButton) {
          refreshButton.removeEventListener("click", refreshHandler);
        }
      });
    }
    closeModal(overlay) {
      this.diagnosticsExpanded = false;
      this.modalCleanupCallbacks.forEach((cleanup) => {
        try {
          cleanup();
        } catch (error) {
          this.logger.log(
            "warning",
            "Error during modal cleanup",
            error.message
          );
        }
      });
      this.modalCleanupCallbacks = [];
      if (overlay) overlay.remove();
    }
    async saveSettings(overlay) {
      const newConfig = {
        appKey: document.getElementById("dropbox-app-key").value.trim(),
        syncInterval:
          parseInt(document.getElementById("sync-interval").value) || 15,
        encryptionKey: document.getElementById("encryption-key").value.trim(),
      };
      const exclusions = document.getElementById("sync-exclusions").value;
      localStorage.setItem("tcs_sync-exclusions", exclusions);
      this.config.reloadExclusions();
      if (
        !newConfig.appKey ||
        !newConfig.encryptionKey
      ) {
        alert("Please fill in all required Dropbox settings (App Key and Encryption Key)");
        return;
      }
      if (newConfig.syncInterval < 15) {
        alert("Sync interval must be at least 15 seconds");
        return;
      }
      const saveButton = document.getElementById("save-settings");
      const actionMsg = document.getElementById("action-msg");
      saveButton.disabled = true;
      saveButton.textContent = "Saving...";
      actionMsg.textContent = "Saving configuration...";
      actionMsg.style.color = "#3b82f6";
      try {
        // Check if user is authenticated with Dropbox
        if (!this.config.get("accessToken")) {
          actionMsg.textContent =
            "⚠️ Please authenticate with Dropbox first by clicking the 'Authenticate' button";
          actionMsg.style.color = "#eab308";
          saveButton.disabled = false;
          saveButton.textContent = "Save";
          return;
        }

        // Verify Dropbox connection by attempting to list root
        const tempConfigManager = {
          config: { ...this.config.config, ...newConfig },
          get: function (key) {
            return this.config[key];
          },
          isConfigured: () => true,
        };
        const tempDropboxService = new DropboxService(
          tempConfigManager,
          this.cryptoService,
          this.logger,
          this.dropboxAuth
        );
        await tempDropboxService.initialize();
        await tempDropboxService.list("");
        actionMsg.textContent =
          "✅ Dropbox connection verified! Saving configuration...";
        actionMsg.style.color = "#22c55e";
        Object.keys(newConfig).forEach((key) =>
          this.config.set(key, newConfig[key])
        );
        this.config.save();
        if (!this.noSyncMode) {
          this.operationQueue.add(
            "save-and-sync",
            async () => {
              await this.s3Service.initialize();
              await this.syncOrchestrator.performFullSync();
              this.startAutoSync();
              this.updateSyncStatus("success");
              this.logger.log(
                "success",
                "Configuration saved and sync completed"
              );
            },
            "high"
          );
        } else {
          this.operationQueue.add(
            "save-config-nosync",
            async () => {
              await this.s3Service.initialize();
              this.logger.log(
                "success",
                "Configuration saved (NoSync mode - only snapshot available)"
              );
            },
            "high"
          );
        }
        setTimeout(() => {
          this.closeModal(overlay);
        }, 1500);
      } catch (error) {
        this.logger.log("error", "Dropbox connection verification failed", error);
        let errorMessage =
          "Verification failed. Please check your Dropbox authentication and permissions.";
        if (error.status === 401) {
          errorMessage =
            "Verification failed: Invalid or expired access token. Please re-authenticate.";
        } else if (error.status === 403) {
          errorMessage =
            "Verification failed: Access Denied. Ensure your app has the required permissions.";
        } else if (error.status === 429) {
          errorMessage =
            "Verification failed: Rate limit exceeded. Please try again later.";
        }
        actionMsg.textContent = `❌ ${errorMessage}`;
        actionMsg.style.color = "#ef4444";
        saveButton.disabled = false;
        saveButton.textContent = "Save";
      }
    }
    async authenticateDropbox() {
      // Save the app key first if it's been entered
      const appKeyInput = document.getElementById("dropbox-app-key");
      if (appKeyInput && appKeyInput.value.trim()) {
        this.config.set("appKey", appKeyInput.value.trim());
        this.config.save();
        this.logger.log("info", "Saved Dropbox App Key");
      }

      // Check if app key is configured
      if (!this.config.get("appKey")) {
        alert("Please enter your Dropbox App Key first");
        return;
      }

      try {
        // Generate and redirect to Dropbox OAuth URL
        const authUrl = await this.dropboxAuth.getAuthUrl();
        this.logger.log("info", "Redirecting to Dropbox authorization...");
        window.location.href = authUrl;
      } catch (error) {
        this.logger.log("error", "Failed to initiate Dropbox OAuth", error.message);
        alert(`Failed to authenticate with Dropbox: ${error.message}`);
      }
    }
    async createSnapshot() {
      if (!this.isSnapshotAvailable()) {
        alert(
          "⚠️ Snapshot Unavailable\n\nSnapshots require Dropbox configuration. Please configure the following mandatory fields:\n• Dropbox App Key\n• Encryption Key\n\nThen authenticate with Dropbox using OAuth."
        );
        return;
      }
      const name = prompt("Enter snapshot name:");
      if (!name) return;
      const modal = document.querySelector(".cloud-sync-modal");
      const snapshotButton = modal?.querySelector("#create-snapshot");
      if (snapshotButton) {
        const originalText = snapshotButton.textContent;
        snapshotButton.disabled = true;
        snapshotButton.textContent = "In Progress...";
        try {
          await this.backupService.createSnapshot(name);
          snapshotButton.textContent = "Success!";
          await this.loadBackupList(modal);
          setTimeout(() => {
            snapshotButton.textContent = originalText;
            snapshotButton.disabled = false;
          }, 2000);
          alert("Snapshot created successfully!");
        } catch (error) {
          this.logger.log("error", "Failed to create snapshot", error.message);
          snapshotButton.textContent = "Failed";
          setTimeout(() => {
            snapshotButton.textContent = originalText;
            snapshotButton.disabled = false;
          }, 2000);
          alert("Failed to create snapshot: " + error.message);
        }
      } else {
        try {
          await this.backupService.createSnapshot(name);
          alert("Snapshot created successfully!");
        } catch (error) {
          this.logger.log("error", "Failed to create snapshot", error.message);
          alert("Failed to create snapshot: " + error.message);
        }
      }
    }
    async deleteBackupWithChunks(key) {
      this.logger.log("start", `Deleting backup: ${key}`);
      if (key.endsWith("-metadata.json")) {
        this.logger.log("info", "Deleting chunked backup with all chunks");
        try {
          const metadata = await this.s3Service.download(key, true);
          let deletedCount = 0;
          if (metadata.chunkList && metadata.chunkList.length > 0) {
            this.logger.log(
              "info",
              `Deleting ${metadata.chunkList.length} chunk files`
            );
            const deletePromises = metadata.chunkList.map(async (chunkInfo) => {
              try {
                await this.s3Service.delete(chunkInfo.filename);
                deletedCount++;
                this.logger.log("info", `Deleted chunk: ${chunkInfo.filename}`);
              } catch (error) {
                this.logger.log(
                  "warning",
                  `Failed to delete chunk ${chunkInfo.filename}: ${error.message}`
                );
              }
            });
            await Promise.allSettled(deletePromises);
          }
          await this.s3Service.delete(key);
          this.logger.log(
            "success",
            `Deleted chunked backup: ${key} (${deletedCount} chunks + metadata)`
          );
        } catch (error) {
          this.logger.log(
            "warning",
            `Failed to read metadata for ${key}, attempting to delete file anyway`
          );
          await this.s3Service.delete(key);
        }
      } else {
        this.logger.log("info", "Deleting simple backup");
        await this.s3Service.delete(key);
        this.logger.log("success", `Deleted simple backup: ${key}`);
      }
    }
    startAutoSync() {
      if (this.autoSyncInterval) clearInterval(this.autoSyncInterval);
      const interval = Math.max(this.config.get("syncInterval") * 1000, 15000);
      this.autoSyncInterval = setInterval(async () => {
        if (
          this.config.isConfigured() &&
          !this.syncOrchestrator.syncInProgress
        ) {
          try {
            const backupWasPerformed =
              await this.backupService.checkAndPerformDailyBackup();
            if (!backupWasPerformed) {
              await this.syncOrchestrator.performFullSync();
            }
          } catch (error) {
            this.logger.log("error", "Auto-sync failed", error.message);
          }
        }
      }, interval);
      this.logger.log("info", "Auto-sync started");
    }
    async getCloudMetadata() {
      const { metadata } = await this.getCloudMetadataWithETag();
      return metadata;
    }
    cleanup() {
      this.logger.log("info", "🧹 Starting comprehensive cleanup");
      if (this.autoSyncInterval) {
        clearInterval(this.autoSyncInterval);
        this.autoSyncInterval = null;
      }
      this.modalCleanupCallbacks.forEach((cleanup) => {
        try {
          cleanup();
        } catch (error) {
          console.warn("Modal cleanup error:", error);
        }
      });
      this.modalCleanupCallbacks = [];
      this.eventListeners.forEach(({ element, event, handler }) => {
        try {
          element.removeEventListener(event, handler);
        } catch (error) {
          console.warn("Event listener cleanup error:", error);
        }
      });
      this.eventListeners = [];
      const existingModal = document.querySelector(".cloud-sync-modal");
      if (existingModal) {
        existingModal.closest(".modal-overlay")?.remove();
      }
      if (this.operationQueue) {
        this.operationQueue.cleanup();
      }
      if (this.dataService) {
        this.dataService.cleanup();
      }
      if (this.cryptoService) {
        this.cryptoService.cleanup();
      }
      if (this.syncOrchestrator) {
        this.syncOrchestrator.cleanup();
      }
      this.logger.log("success", "✅ Cleanup completed");
      this.config = null;
      this.dataService = null;
      this.cryptoService = null;
      this.s3Service = null;
      this.syncOrchestrator = null;
      this.backupService = null;
      this.operationQueue = null;
      this.logger = null;
      this.leaderElection = null;
    }
    async runLeaderTasks() {
      if (!this.noSyncMode && this.config.isConfigured()) {
        this.updateSyncStatus("syncing");
        try {
          await this.syncOrchestrator.performFullSync();
          this.startAutoSync();
          this.updateSyncStatus("success");
          this.logger.log("success", "Cloud Sync initialized on leader tab.");
        } catch (error) {
          this.logger.log(
            "error",
            "Background sync/backup failed on leader tab",
            error.message
          );
          this.updateSyncStatus("error");
        }
      }
    }
  }
  const styleSheet = document.createElement("style");
  styleSheet.textContent = `
    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background-color: rgba(0, 0, 0, 0.6);
      backdrop-filter: blur(4px);
      z-index: 99999;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1rem;
      overflow-y: auto;
    }
    
    #sync-status-dot {
      position: absolute;
      top: -0.15rem;
      right: -0.6rem;
      width: 0.625rem;
      height: 0.625rem;
      border-radius: 9999px;
    }
    
    .cloud-sync-modal {
      width: 100%;
      max-width: 32rem;
      background-color: rgb(39, 39, 42);
      color: white;
      border-radius: 0.5rem;
      padding: 1rem;
      border: 1px solid rgba(255, 255, 255, 0.1);
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3);
    }
    
    .cloud-sync-modal input,
    .cloud-sync-modal select {
      background-color: rgb(63, 63, 70);
      border: 1px solid rgb(82, 82, 91);
      color: white;
    }
    
    .cloud-sync-modal input:focus,
    .cloud-sync-modal select:focus {
      border-color: rgb(59, 130, 246);
      outline: none;
      box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
    }
    
    .cloud-sync-modal button:disabled {
      background-color: rgb(82, 82, 91);
      cursor: not-allowed;
      opacity: 0.5;
    }
    
    .cloud-sync-modal .bg-zinc-800 {
      border: 1px solid rgb(82, 82, 91);
    }
    
    .cloud-sync-modal input[type="checkbox"] {
      accent-color: rgb(59, 130, 246);
    }
    
    .cloud-sync-modal input[type="checkbox"]:checked {
      background-color: rgb(59, 130, 246);
      border-color: rgb(59, 130, 246);
    }
    
    #sync-diagnostics-table {
      font-size: 0.75rem;
    }
    
    #sync-diagnostics-table th {
      background-color: rgb(82, 82, 91);
      font-weight: 600;
    }
    
    #sync-diagnostics-table tr:hover {
      background-color: rgba(63, 63, 70, 0.5);
    }
    
    #sync-diagnostics-table .bg-orange-900\\/20 {
      background-color: rgba(194, 65, 12, 0.2);
    }
    
    #sync-diagnostics-header {
      padding: 0.5rem;
      margin: -0.5rem;
      border-radius: 0.375rem;
      transition: background-color 0.2s ease;
      -webkit-tap-highlight-color: transparent;
      min-height: 44px;
      display: flex;
      align-items: center;
    }
    
    #sync-diagnostics-header:hover {
      background-color: rgba(63, 63, 70, 0.5);
    }
    
    #sync-diagnostics-header:active {
      background-color: rgba(63, 63, 70, 0.8);
    }
    
    #sync-diagnostics-chevron {
      transition: transform 0.2s ease;
    }
    
    #sync-diagnostics-refresh {
      transition: transform 0.3s ease;
    }
    
    #sync-diagnostics-content {
      animation: slideDown 0.2s ease-out;
    }
    
    @keyframes slideDown {
      from {
        opacity: 0;
        max-height: 0;
      }
      to {
        opacity: 1;
        max-height: 300px;
      }
    }
    
    @media (max-width: 640px) {
      #sync-diagnostics-table {
        font-size: 0.7rem;
      }
      
      #sync-diagnostics-table th,
      #sync-diagnostics-table td {
        padding: 0.5rem 0.25rem;
      }
      
      .cloud-sync-modal {
        margin: 0.5rem;
        max-height: 90vh;
        overflow-y: auto;
      }
    }
  `;
  document.head.appendChild(styleSheet);
  const app = new CloudSyncApp();
  app.initialize();
  window.cloudSyncApp = app;
  const cleanupHandler = () => {
    try {
      app?.cleanup();
    } catch (error) {
      console.warn("Cleanup error:", error);
    }
  };
  const visibilityChangeHandler = () => {
    if (document.hidden) {
      try {
        if (app?.operationQueue) {
          app.operationQueue.cleanupStaleOperations(Date.now());
        }
        if (app?.cryptoService) {
          app.cryptoService.cleanupKeyCache();
        }
      } catch (error) {
        console.warn("Visibility change cleanup error:", error);
      }
    }
  };
  window.addEventListener("beforeunload", cleanupHandler, { passive: true });
  window.addEventListener("unload", cleanupHandler, { passive: true });
  window.addEventListener("pagehide", cleanupHandler, { passive: true });
  document.addEventListener("visibilitychange", visibilityChangeHandler, {
    passive: true,
  });
  window.addEventListener(
    "error",
    (event) => {
      if (
        event.error?.message?.includes("memory") ||
        event.error?.message?.includes("heap")
      ) {
        console.warn(
          "🚨 Potential memory-related error detected:",
          event.error
        );
        window.forceMemoryCleanup?.();
      }
    },
    { passive: true }
  );
  window.createTombstone = (itemId, type, source = "manual") => {
    if (app?.dataService) {
      return app.dataService.createTombstone(itemId, type, source);
    }
    return null;
  };
  window.getTombstones = () => {
    if (app?.dataService) {
      return Array.from(app.dataService.getAllTombstones().entries());
    }
    return [];
  };
  window.getMemoryStats = () => {
    if (app) {
      return {
        knownItems: app.dataService?.knownItems?.size || 0,
        operationQueue: app.operationQueue?.size() || 0,
        eventListeners: app.eventListeners?.length || 0,
        modalCallbacks: app.modalCleanupCallbacks?.length || 0,
      };
    }
    return {};
  };
  window.estimateBackupSize = async () => {
    if (app?.backupService && app?.dataService) {
      const { totalSize, itemCount } = await app.dataService.estimateDataSize();
      const chunkLimit = app.backupService.chunkSizeLimit;
      const willUseChunks = totalSize > chunkLimit;
      const willUseStreaming = totalSize > app.dataService.memoryThreshold;
      return {
        estimatedSize: totalSize,
        formattedSize: app.dataService.formatSize(totalSize),
        itemCount: itemCount,
        chunkLimit: chunkLimit,
        formattedChunkLimit: app.dataService.formatSize(chunkLimit),
        memoryThreshold: app.dataService.memoryThreshold,
        formattedMemoryThreshold: app.dataService.formatSize(
          app.dataService.memoryThreshold
        ),
        willUseChunks: willUseChunks,
        willUseStreaming: willUseStreaming,
        backupMethod: willUseChunks ? "chunked" : "simple",
        processingMethod: willUseStreaming ? "streaming" : "in-memory",
        compressionNote:
          "Size shown is before ZIP compression (expect ~70% reduction)",
      };
    }
    return { error: "Services not available" };
  };
  window.getMemoryDiagnostics = () => {
    const diagnostics = {
      timestamp: new Date().toISOString(),
      performance: {},
      app: {},
      browser: {},
    };
    try {
      if (performance?.memory) {
        diagnostics.performance = {
          usedJSHeapSize: performance.memory.usedJSHeapSize,
          totalJSHeapSize: performance.memory.totalJSHeapSize,
          jsHeapSizeLimit: performance.memory.jsHeapSizeLimit,
          usedHeapMB: Math.round(
            performance.memory.usedJSHeapSize / 1024 / 1024
          ),
          totalHeapMB: Math.round(
            performance.memory.totalJSHeapSize / 1024 / 1024
          ),
          limitHeapMB: Math.round(
            performance.memory.jsHeapSizeLimit / 1024 / 1024
          ),
          heapUsagePercent: Math.round(
            (performance.memory.usedJSHeapSize /
              performance.memory.jsHeapSizeLimit) *
              100
          ),
        };
      }
      if (app) {
        diagnostics.app = {
          hasDataService: !!app.dataService,
          hasCryptoService: !!app.cryptoService,
          hasS3Service: !!app.s3Service,
          hasSyncOrchestrator: !!app.syncOrchestrator,
          hasBackupService: !!app.backupService,
          hasOperationQueue: !!app.operationQueue,
          operationQueueSize: app.operationQueue?.size() || 0,
          eventListenersCount: app.eventListeners?.length || 0,
          modalCallbacksCount: app.modalCleanupCallbacks?.length || 0,
          cryptoKeyCacheSize: app.cryptoService?.keyCache?.size || 0,
          syncInProgress: app.syncOrchestrator?.syncInProgress || false,
          autoSyncInterval: !!app.autoSyncInterval,
          diagnosticsInterval: !!app.diagnosticsInterval,
        };
      }
      diagnostics.browser = {
        userAgent: navigator.userAgent,
        language: navigator.language,
        platform: navigator.platform,
        hardwareConcurrency: navigator.hardwareConcurrency,
        cookieEnabled: navigator.cookieEnabled,
        onLine: navigator.onLine,
        doNotTrack: navigator.doNotTrack,
      };
      if (window?.gc || (typeof global !== "undefined" && global?.gc)) {
        diagnostics.performance.gcAvailable = true;
      }
    } catch (error) {
      diagnostics.error = error.message;
    }
    return diagnostics;
  };
  window.forceMemoryCleanup = async () => {
    console.log("🧹 Starting forced memory cleanup...");
    try {
      if (app?.dataService?.forceGarbageCollection) {
        await app.dataService.forceGarbageCollection();
      }
      if (app?.cryptoService?.cleanupKeyCache) {
        app.cryptoService.cleanupKeyCache();
      }
      if (app?.operationQueue?.cleanupStaleOperations) {
        app.operationQueue.cleanupStaleOperations(Date.now());
      }
      const modal = document.querySelector(".cloud-sync-modal");
      if ((modal && !modal.style.display) || modal.style.display !== "none") {
        console.log("Modal is open, skipping DOM cleanup");
      } else {
        const orphanedElements = document.querySelectorAll(
          "[data-temporary='true']"
        );
        orphanedElements.forEach((el) => el.remove());
      }
      if (window?.gc) {
        window.gc();
        console.log("✅ Manual garbage collection triggered");
      } else if (typeof global !== "undefined" && global?.gc) {
        global.gc();
        console.log("✅ Manual garbage collection triggered (global)");
      } else {
        console.log("⚠️ Manual garbage collection not available");
      }
      console.log("✅ Memory cleanup completed");
      return window.getMemoryDiagnostics();
    } catch (error) {
      console.error("❌ Memory cleanup failed:", error);
      return { error: error.message };
    }
  };
}
