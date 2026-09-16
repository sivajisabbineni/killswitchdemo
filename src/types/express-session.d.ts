import 'express-session';

declare module 'express-session' {
  interface SessionData {
    oauthState?: string;
    loginFlow?: 'resource' | 'agent' | 'm2m';
    userAccessToken?: string;
    userIdToken?: string;
  }
}
