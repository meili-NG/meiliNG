module.exports = {
  node: {
    /** Overwrite Node **/
    environment: 'development',
  },
  frontend: {
    /** Please enter the frontend address. Used for cors origin and login redirects. */
    url: ['https://login.appie.stella-it.com', 'https://meiling-dev.stella-it.com', 'http://localhost:3000'],
  },
  openid: {
    /** The name to be set as the JWT issuer. */
    issuingAuthority: 'https://meiling.stella-api.dev',
    /** OPENID JWT encryption/decryption key. */
    jwt: {
      algorithm: 'RS256',
      keyId: 'meiliNG OpenID Signature Key',
      publicKey: {
        key: '',
        passphrase: undefined,
      },
      privateKey: {
        key: '',
        passphrase: undefined,
      },
    },
  },
  fastify: {
    /** Specifies the port number or socket file location. */
    listen: 3000,
    /** Please enter your listening address. */
    address: '0.0.0.0',
    /** Set this to undefined if you don't have any proxies */
    proxy: {
      /** Please enter the proxy address to allow. */
      allowedHosts: [],
    },
    unixSocket: {
      /** Sets the permissions of UNIX Socket. */
      chmod: '0777',
    },
  },
  meiling: {
    /** The hostname of the meiling, give the public URL origin of this API. */
    hostname: 'https://meiling.stella-api.dev',
    /** The following URL will be filled with errorcode on error, and sent to user */
    error: {
      urlFormat: 'https://opensource.stella-it.com/developers/docs/meiling/error/{{errorCode}}.html',
    },
    /** Specify the applications to skip the authentication steps. This should be strictly used in INTERNAL Apps with CLIENT_SECRET. */
    oauth2: {
      /** List the client_id of applications to skip the authentication steps */
      skipAuthentication: [],
      /** Configurations for Device Code Authentication */
      deviceCode: {
        /**
         * verification url to redirect when device code request was received.
         * make it short! (about 40 chars long)
         **/
        verification_url: 'http://localhost:3000/device',
        /** polling interval to send on device code requests */
        interval: 5,
      },
    },
    /** should meiling generate duplicates? */
    preventDuplicates: {
      /**  */
      email: false,
      phone: false,
    },
    /** Signup configuration - meiliNG Internal */
    signup: {
      /** Enable meiliNG Internal Signup? set it to false to disable (e.g. only use custom signup process) */
      enabled: !/^false$/i.test(process.env.MEILING_SIGNUP_ENABLED || ''),
    },
  },
  session: {
    /** Configures Version 1 of the meiliNG Session */
    v1: {
      /** Maximum Age of Session (in seconds) */
      maxAge: 604800,
      /** Rate Limit */
      rateLimit: {
        /** How many tokens will meiling allow generating on per IP */
        maxTokenPerIP: 20,
        /** Preceding rate limit will applied to following time window */
        timeframe: 600,
      },
    },
  },
  token: {
    /** Configure token generators */
    generators: {
      /** Default generator config */
      default: {
        /** which characters are you going to allow in the token */
        chars: 'QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890',
        /** length of the token */
        length: 128,
      },
      /** TODO: Implement generators */
      tokens: {},
    },
    /** Token Invalidation Config */
    invalidate: {
      /** Configures Invalidation timeframe of oauth tokens */
      oauth: {
        AUTHORIZATION_CODE: 300,
        ACCESS_TOKEN: 7200,
        REFRESH_TOKEN: 604800,
        ACCOUNT_TOKEN: -1,
      },
      /** Configures Invalidation timeframe of openid id_token */
      openid: 300,
      /** Configures Invalidation timeframe of meiling's token */
      meiling: {
        CHALLENGE_TOKEN: 300,
        CHALLENGE_TOKEN_SMS_RATE_LIMIT: 60,
        CHALLENGE_TOKEN_EMAIL_RATE_LIMIT: 60,
      },
    },
  },
  sentry: {
    serverName: undefined,
    dsn: 'https://this-is-example-dsn.ingest.sentry.io/sample-baby',
  },
  notificationApi: {
    /** Use notification api? (Stella IT Proprietary, Set it to false if you don't use one.) */
    enable: true,
    version: 1,
    host: 'https://notification.stella-api.dev',
    key: 'YOUR NOTIFICATION API KEY',
    settings: {
      useAlimtalkForSouthKorea:
        /^true$/gi.test(process.env.NOTIFICATION_API_SETTINGS_USE_ALIMTALK_FOR_SOUTH_KOREA) || false,
    },
  },
  baridegiApi: {
    version: 1,
    host: 'https://baridegi.stella-api.dev',
    serverId: 'baridegi_serverId',
    integrationId: 'baridegi_integrationId',
    token: 'baridegi_token',
  },
  admin: {
    /** Configures admin tokens for calling /admin endpoints */
    tokens: [],
    frontend: {
      url: [],
    },
  },
};
