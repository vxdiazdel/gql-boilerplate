import { Response } from 'express';
import { sign } from 'jsonwebtoken';
import { User } from 'src/entity/User';

export const createAccessToken = (user: User) => {
  return sign({ userId: user.id }, process.env.ACCESS_TOKEN_SECRET!, {
    expiresIn: '15m',
  });
};

export const createRefreshToken = (user: User) => {
  return sign(
    { userId: user.id, tokenVersion: user.tokenVersion },
    process.env.REFRESH_TOKEN_SECRET!,
    {
      expiresIn: '7d',
    },
  );
};

export const sendRefreshToken = (res: Response, token: String) => {
  res.cookie('uid', token, { httpOnly: true });
};
