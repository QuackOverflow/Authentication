import { Module } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { LoginUseCase } from 'src/application/use_cases/login.use_case';
import { LogoutUseCase } from 'src/application/use_cases/logout.use_case';
import { RefreshTokenUseCase } from 'src/application/use_cases/refresh_token.use_case';
import { RefreshTokenEntity } from 'src/infrastructure/database/entities/refresh_token.entity';
import { UserEntity } from 'src/infrastructure/database/entities/user.entity';
import { BcryptCryptoGateway } from 'src/infrastructure/gateways/bcrypt_crypto.gateway';
import { JwtTokenGateway } from 'src/infrastructure/gateways/jwt_token.gateway';
import { TypeOrmRefreshTokenRepository } from 'src/infrastructure/repositories/refresh_token_repository';
import { TypeOrmUserRepository } from 'src/infrastructure/repositories/user_repository';
import { AuthController } from 'src/presentation/controllers/auth.controller';
import { CreateUserUseCase } from '../application/use_cases/create_user';
import { AdminCreateUserUseCase } from '../application/use_cases/admin_create_user';

@Module({
  imports: [
    TypeOrmModule.forFeature([UserEntity]),
    TypeOrmModule.forFeature([RefreshTokenEntity]),
  ],
  controllers: [AuthController],
  providers: [
    {
      provide: 'RefreshTokenRepository',
      useClass: TypeOrmRefreshTokenRepository,
    },
    {
      provide: 'UserRepository',
      useClass: TypeOrmUserRepository,
    },
    {
      provide: 'TokenGateway',
      useClass: JwtTokenGateway,
    },
    {
      provide: 'CryptoGateway',
      useClass: BcryptCryptoGateway,
    },

    JwtService,

    // Use cases
    AdminCreateUserUseCase,
    CreateUserUseCase,
    LoginUseCase,
    LogoutUseCase,
    RefreshTokenUseCase,
  ],
  exports: [
    'RefreshTokenRepository',
    'UserRepository',
    'TokenGateway',
    'CryptoGateway',
  ],
})
export class AuthModule {}
