import * as SMTPConnection from 'nodemailer/lib/smtp-connection'
import Debug from 'debug'

const log = Debug('duplo:smtp-authenticator')

export interface AuthenticationResult {
	success: boolean
	domain: string
	username: string
}

export function authenticate(username: string, password: string, domain: string, host: string) {
	log(`authenticating ${username}`)
	return new Promise<AuthenticationResult>((resolve, reject) => {
		const connection = new SMTPConnection({
			port: 465,
			host,
			secure: true,
			requireTLS: true,
		})

		connection
			.on('error', reject)
			.on('end', () => connection.close())

		log(`connecting`)
		connection.connect(() => {
			log(`logging in`)
			connection.login({
				user: `${username}@${domain}`,
				pass: password
			}, err => {
				connection.quit()
				if (err) {
					log(`failed to login ${username}`, err.message, err)
					reject(err)
				} else {
					log(`successfully authenticated ${username}`)
					resolve({
						domain,
						username,
						success: true
					})
				}
			})
		})
	})
}