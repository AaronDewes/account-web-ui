import { serverSupabaseServiceRole, serverSupabaseUser } from '#supabase/server'
import { SupabaseClient } from "@supabase/supabase-js"
import { Database } from '~~/types/db';
import * as crypto from 'crypto';
import cloudflare from "cloudflare";
import is_ip_private from 'private-ip';


// Generate a random hex string with the given length
const randomString = (length: number) => crypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length);

type ApiResponse = {
    subdomain: string;
} | {
    error: string;
};

export default defineEventHandler(async (event): Promise<ApiResponse> => {
    const cf = new cloudflare({
        token: process.env.CLOUDFLARE_TOKEN
    });
    if (event.req.method !== 'GET' && event.req.method !== 'POST' && event.req.method !== 'PUT') {
        event.res.statusCode = 405;
        event.res.setHeader('Allow', 'GET, POST, PUT');
        return {
            error: "Method not allowed"
        };
    }
    const user = await serverSupabaseUser(event);
    if (!user.id || !user.confirmed_at) {
        event.res.statusCode = 401;
        return {
            error: "Permission denied"
        };
    }
    if (event.req.method === 'GET') {
        let subdomain = randomString(8);
        let secret = randomString(128);
        const { error } = await supabase.from("subdomains").insert({
            domain: subdomain,
            secret,
        });

        if (error) {
            event.res.statusCode = 500;
            return {
                error: error.message
            };
        }
        
        return {
            domain: subdomain,
            secret,
        };
    }
    const supabase = serverSupabaseServiceRole(event) as SupabaseClient<Database>;
    const body: {
        subdomain?: string;
        secret?: string;
        record_type: "A" | "AAAA" | "TXT";
        content: string;
    } = await useBody(event);

    if (typeof body?.record_type !== 'string' || typeof body?.content !== 'string') {
        event.res.statusCode = 400;
        return {
            error: 'Invalid data'
        };
    }

    if (!["A", "AAAA", "TXT"].includes(body.record_type)) {
        event.res.statusCode = 400;
        return {
            error: 'Only A, AAAA and TXT records are supported'
        };
    }

    if ((body.record_type === "A" || body.record_type === "AAAA") && !is_ip_private(body.content)) {
        event.res.statusCode = 400;
        return {
            error: 'Only private IP addresses are supported.'
        };
    }

    let subdomain = "";
    if (typeof body.subdomain === 'string') {
        let path = body.subdomain.split(".");
        const { data } = await supabase.from("subdomains").select().eq("subdomain", path[path.length - 1]).maybeSingle();
        if (!data) {
            event.res.statusCode = 404;
            return {
                error: 'Subdomain not found'
            };
        }
        if (data.secret !== body.secret) {
            event.res.statusCode = 403;
            return {
                error: 'Permission denied'
            };
        }
        subdomain = data.domain;
    } else {
            event.res.statusCode = 400;
            return {
                error: 'Missing subdomain'
            };
    }

    try {
        await cf.dnsRecords.add(process.env.CLOUDFLARE_LOCAL_ZONE_ID, {
            type: body.record_type,
            name: subdomain,
            content: body.content,
            ttl: 3600,
            proxied: true,
        });
    } catch (error) {
        console.error(error);
        return {
            error: "Error adding DNS record"
        };
    }

    event.res.statusCode = 200;
    return {
        subdomain,
    };
});
