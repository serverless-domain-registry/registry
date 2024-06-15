class Epusdt {
    baseUrl: string;
    signKey: string;

    constructor(url: string, signKey: string) {
        this.baseUrl = url;
        this.signKey = signKey;
    }

    async sign(parameters: {[key: string]: string|number}, signKey: string): Promise<string> {
        const keys = Object.keys(parameters).sort();
        let sign = '';
        let urls = '';

        keys.forEach(key => {
            const val = parameters[key];
            if (val === '' || key === 'signature') return;

            if (sign !== '') {
                sign += '&';
                urls += '&';
            }

            sign += `${key}=${val}`;
            urls += `${key}=${encodeURIComponent(val)}`;
        });

        const data = new TextEncoder().encode(sign + signKey);
        const hashBuffer = await crypto.subtle.digest('MD5', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex;
    }

    async makeCall(url: string, parameter: {[key: string]: string|number}): Promise<any> {
        parameter.signature = await this.sign(parameter, this.signKey);
        try {
            const response = await fetch(this.baseUrl + url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(parameter)
            });

            const resp = <{status: Number; status_code: Number; message: string; data: any;}> await response.json();

            if (response.status !== 200 || resp.status_code !== 200) {
                throw new Error(resp.message);
            }

            return resp.data;
        } catch (error) {
            throw new Error(`HTTP error: ${error.message}`);
        }
    }

    async createTransaction(orderNumber: string, cnyAmount: number, notifyUrl: string): Promise<any> {
        const parameter = {
            order_id: orderNumber,
            amount: parseFloat(parseFloat(<any> cnyAmount).toFixed(2)),
            notify_url: notifyUrl,
            redirect_url: notifyUrl
        };

        return await this.makeCall('/api/v1/order/create-transaction', parameter);
    }

    async notify(request: Request, callback: (request: Request) => any): Promise<string> {
        const json = <any> await request.clone().json();
        const assertSignature = await this.sign(json, this.signKey);
        const realSignature = json.signature;

        if (assertSignature !== realSignature) {
            throw new Error('Signature mismatch');
        }

        const callbackResult = await callback(request);
        if (!callbackResult) {
            throw new Error('Callback processing failed');
        }

        return 'ok';
    }
}

export default Epusdt;
