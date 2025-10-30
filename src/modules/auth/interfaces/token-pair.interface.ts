export interface TokenPair {
  accessToken: string;
  refreshToken: string; // plain token (only returned once on rotation), server stores hash
  accessTokenExpiresIn: number; // seconds
  refreshTokenExpiresAt: Date;
}
