import { randomUUID } from 'crypto';

export class RefreshToken {
  constructor(
    private readonly _id: string,
    private readonly _userId: string,
    private readonly _tokenHash: string, // Hash of the refresh token
    private readonly _expiresAt: Date,
    private readonly _createdAt: Date,
    private _isRevoked: boolean = false,
    private _revokedAt?: Date,
  ) {}

  static create(data: {
    userId: string;
    tokenHash: string;
    expiresAt: Date;
  }): RefreshToken {
    return new RefreshToken(
      randomUUID(),
      data.userId,
      data.tokenHash,
      data.expiresAt,
      new Date(),
      false,
    );
  }

  static reconstitute(data: {
    id: string;
    userId: string;
    tokenHash: string;
    expiresAt: Date;
    createdAt: Date;
    isRevoked?: boolean;
    revokedAt?: Date;
  }): RefreshToken {
    return new RefreshToken(
      data.id,
      data.userId,
      data.tokenHash,
      data.expiresAt,
      data.createdAt,
      data.isRevoked || false,
      data.revokedAt,
    );
  }

  revoke(): void {
    this._isRevoked = true;
    this._revokedAt = new Date();
  }

  isValid(): boolean {
    return !this._isRevoked && new Date() < this._expiresAt;
  }

  isExpired(): boolean {
    return new Date() > this._expiresAt;
  }

  // Getters
  get id(): string {
    return this._id;
  }
  get userId(): string {
    return this._userId;
  }
  get tokenHash(): string {
    return this._tokenHash;
  }
  get createdAt(): Date {
    return this._createdAt;
  }
  get expiresAt(): Date {
    return this._expiresAt;
  }
  get isRevoked(): boolean {
    return this._isRevoked;
  }
}
