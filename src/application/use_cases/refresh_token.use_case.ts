import { Inject, Injectable } from '@nestjs/common';
import { IUserRepository } from '../interfaces/user_repository';
import { RefreshToken } from 'src/domain/entities/refresh_token.entity';
import {
  InvalidCredentialsError,
  InvalidTokenError,
  RefreshTokenRevokedError,
} from 'src/domain/exceptions/auth.exceptions';
import { JwtPayload } from 'src/domain/value_objects/jwt_payload';
import { RefreshTokenRequest } from '../dtos/refresh_token_request';
import { RefreshTokenResponse } from '../dtos/refresh_token_response';
import { IRefreshTokenRepository } from '../interfaces/refresh_token_repository';
import { ITokenGateway } from '../interfaces/token_gateway';
import { IUseCase } from '../interfaces/use_case';

@Injectable()
export class RefreshTokenUseCase
  implements IUseCase<RefreshTokenRequest, RefreshTokenResponse>
{
  constructor(
    @Inject('UserRepository')
    private readonly userRepository: IUserRepository,
    @Inject('RefreshTokenRepository')
    private readonly refreshTokenRepository: IRefreshTokenRepository,
    @Inject('TokenGateway')
    private readonly tokenGateway: ITokenGateway,
  ) {}

  async execute({
    refreshToken,
  }: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    // 1. Verify JWT structure first (to get userId)
    let payload: { userId: string; token?: string };
    try {
      payload = await this.tokenGateway.verifyRefreshToken(refreshToken);
    } catch (error) {
      console.error(error);
      throw new InvalidTokenError();
    }

    // 2. Find token by verifying against stored hashes
    const storedRefreshToken =
      await this.refreshTokenRepository.findByTokenAndUserId(
        refreshToken,
        payload.userId,
      );

    if (!storedRefreshToken || !storedRefreshToken.isValid()) {
      throw new RefreshTokenRevokedError();
    }

    // 3. Verify user still exists
    const user = await this.userRepository.findById(payload.userId);
    if (!user) {
      // Revoke the refresh token if user is suspended
      await this.refreshTokenRepository.revokeAllByUserId(payload.userId);
      throw new InvalidCredentialsError();
    }

    // 4. Generate new access token
    const jwtPayload = JwtPayload.create({
      userId: user.id,
      email: user.email,
      roles: [user.role],
    });

    const newAccessToken =
      await this.tokenGateway.generateAccessToken(jwtPayload);

    // 5. Generate new refresh token (token rotation for security)
    const newRefreshTokenData = await this.tokenGateway.generateRefreshToken(
      user.id,
    );

    // 6. Revoke old refresh token and save new one
    await this.refreshTokenRepository.revokeByTokenHash(
      storedRefreshToken.tokenHash,
    );

    const newRefreshToken = RefreshToken.create({
      userId: user.id,
      tokenHash: newRefreshTokenData.tokenHash,
      expiresAt: newRefreshTokenData.expiresAt,
    });

    await this.refreshTokenRepository.save(newRefreshToken);

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshTokenData.token,
      expiresAt: jwtPayload.expiresAt,
    };
  }
}
