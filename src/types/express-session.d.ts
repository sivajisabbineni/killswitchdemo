import 'express-session';

declare module 'express-session' {
  interface SessionData {
    oauthState?: string;
    loginFlow?: 'resource' | 'agent';
    userAccessToken?: string;
    userIdToken?: string;
  }
}
