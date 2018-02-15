import Debug from 'debug'
import { RadiusAuthServer } from './radius-server'
import { SECRET, PORT, ADDRESS, DOMAIN, SMTP_HOST } from './settings'

const log = Debug('main')

log(`starting radius authentication server for ${DOMAIN}`)
const server = new RadiusAuthServer({
	secret: SECRET,
	address: ADDRESS,
	domain: DOMAIN,
	port: PORT,
	smtp: {
		host: SMTP_HOST
	}
})
	.on('authenticated', ({ address, username }) => log(`authenticated ${username}`))
	.on('error', error => console.error(error))
	.bind()
