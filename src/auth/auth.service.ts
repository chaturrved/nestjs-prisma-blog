import { Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {

    constructor(private prisma: PrismaService, private jwtService: JwtService) {}

    async login(email: string, password: string) {
        const user = await this.prisma.user.findUnique({where: {email: email}});

        if(!user) {
            throw new NotFoundException(`No user found for email: ${email}`);
        }

        const isPassWordValid = await bcrypt.compare(user.password, password);

        if(!isPassWordValid) {
            throw new UnauthorizedException(`Invalid password`);
        }

        return {
            accessToken: this.jwtService.sign({userId: user.id}),
        };
    }
}
