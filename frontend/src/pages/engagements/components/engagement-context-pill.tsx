import { ShieldCheck } from 'lucide-react';

import { cn } from '@/lib/utils';

interface EngagementContextPillProps {
    className?: string;
    engagement: { client: string; name: string };
}

export function EngagementContextPill({ className, engagement }: EngagementContextPillProps) {
    return (
        <div
            className={cn(
                'bg-muted text-muted-foreground inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs',
                className,
            )}
        >
            <ShieldCheck className="size-3" />
            <span className="text-foreground font-medium">Engagement:</span>
            <span className="text-foreground">{engagement.name}</span>
            <span>— {engagement.client}</span>
        </div>
    );
}
