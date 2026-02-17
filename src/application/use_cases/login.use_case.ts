import { Inject, Injectable } from '@nestjs/common';
import { IUseCase } from '../interfaces/use_case';
import { LoginRequest } from '../dtos/login_request';
import { LoginResponse } from '../dtos/login_response';
import { IUserRepository } from '../interfaces/user_repository';
import { IRefreshTokenRepository } from '../interfaces/refresh_token_repository';
import { ICryptoGateway } from '../interfaces/crypto_gateway';
import { ITokenGateway } from '../interfaces/token_gateway';
import { InvalidCredentialsError } from 'src/domain/exceptions/auth.exceptions';
import { JwtPayload } from 'src/domain/value_objects/jwt_payload';
import { RefreshToken } from 'src/domain/entities/refresh_token.entity';

@Injectable()
export class LoginUseCase implements IUseCase<LoginRequest, LoginResponse> {
  constructor(
    @Inject('UserRepository') private readonly userRepository: IUserRepository,
    @Inject('RefreshTokenRepository')
    private readonly refreshTokenRepository: IRefreshTokenRepository,
    @Inject('CryptoGateway') private readonly cryptoGateway: ICryptoGateway,
    @Inject('TokenGateway') private readonly tokenGateway: ITokenGateway,
  ) {}

  async execute(request: LoginRequest): Promise<LoginResponse> {
    // 1. Find and verify user
    const user = await this.userRepository.findByEmail(request.email);
    if (!user) {
      throw new InvalidCredentialsError();
    }

    // 2. Verify password
    const isPasswordValid = await this.cryptoGateway.validate(
      request.password,
      user.password,
    );
    if (!isPasswordValid) {
      throw new InvalidCredentialsError();
    }

    // 4. Generate access token
    const jwtPayload = JwtPayload.create({
      userId: user.id,
      email: user.email,
      roles: [user.role],
    });

    const accessToken = await this.tokenGateway.generateAccessToken(jwtPayload);

    // 5. Generate refresh token (only if remember me or long-term access needed)
    let refreshTokenValue = '';
    // if (request.rememberMe) {
    // TODO: implement rememberMe
    const refreshTokenData = await this.tokenGateway.generateRefreshToken(
      user.id,
    );
    refreshTokenValue = refreshTokenData.token;
    const refreshToken = RefreshToken.create({
      userId: user.id,
      tokenHash: refreshTokenData.tokenHash,
      expiresAt: refreshTokenData.expiresAt,
    });
    await this.refreshTokenRepository.save(refreshToken);

    return {
      accessToken,
      refreshToken: refreshTokenValue,
      expiresAt: jwtPayload.expiresAt,
      userId: user.id,
    };
  }
}
