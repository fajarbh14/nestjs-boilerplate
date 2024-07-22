import { IsEmail, IsString } from 'class-validator';
export class RegisterRequest {
  @IsEmail()
  email: string;

  @IsString()
  name: string;

  @IsString()
  password: string;

  @IsString()
  confirmPassword: string;
}
