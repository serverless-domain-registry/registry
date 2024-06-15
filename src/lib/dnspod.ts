const apiBase = `https://api.dnspod.com`

export async function createNsRecord(env: any, subdomain: string, dnsservers: string[]): Promise<boolean> {
    const url = `${apiBase}/Record.Create`;

    dnsservers.forEach(async (dnsserver, index) => {
        const json = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: [
                `login_token=${env.DNSPOD_API_ID},${env.DNSPOD_API_TOKEN}`,
                `format=json`,
                `domain_id=${env.DNSPOD_DOMAIN_ID}`,
                `sub_domain=${subdomain}`,
                `record_type=NS`,
                `value=${dnsserver}`,
                `record_line=default`,
                `ttl=3600`,
            ].join(`&`),
        })
    });

    return true;
};

export async function getNsRecord(env: any, subdomain: string): Promise<any[]> {
    const url = `${apiBase}/Record.List`
    return (await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: [
            `login_token=${env.DNSPOD_API_ID},${env.DNSPOD_API_TOKEN}`,
            `format=json`,
            `domain_id=${env.DNSPOD_DOMAIN_ID}`,
            `sub_domain=${subdomain}`,
            `offset=0`,
            `length=500`,
        ].join(`&`),
    })
    .then(res => <{records: any[]}> <unknown> res.json())).records;
};


export async function deleteNsRecord(env: any, subdomain: string) {
    const records = await getNsRecord(env, subdomain);
    records.forEach(async (record: any) => {
        const url = `${apiBase}/Record.Remove`;
        const json = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: [
                `login_token=${env.DNSPOD_API_ID},${env.DNSPOD_API_TOKEN}`,
                `format=json`,
                `domain_id=${env.DNSPOD_DOMAIN_ID}`,
                `record_id=${record.id}`,
            ].join(`&`),
        })
    })
};

export async function updateNsRecord(env: any, subdomain: string, dnsservers: string[]) {
    await deleteNsRecord(env, subdomain);
    return await createNsRecord(env, subdomain, dnsservers);
};

