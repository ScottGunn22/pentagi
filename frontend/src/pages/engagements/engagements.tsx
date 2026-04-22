import { format } from 'date-fns';
import { Plus, ShieldCheck } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';

import { Badge } from '@/components/ui/badge';
import {
    Breadcrumb,
    BreadcrumbItem,
    BreadcrumbList,
    BreadcrumbPage,
} from '@/components/ui/breadcrumb';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { SidebarTrigger } from '@/components/ui/sidebar';
import { StatusCard } from '@/components/ui/status-card';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import { EngagementStatus, useEngagementsQuery } from '@/graphql/types';

const statusVariant: Record<EngagementStatus, 'default' | 'destructive' | 'outline' | 'secondary'> = {
    [EngagementStatus.Active]: 'default',
    [EngagementStatus.Archived]: 'outline',
    [EngagementStatus.Completed]: 'secondary',
    [EngagementStatus.OnHold]: 'outline',
};

const statusLabel: Record<EngagementStatus, string> = {
    [EngagementStatus.Active]: 'Active',
    [EngagementStatus.Archived]: 'Archived',
    [EngagementStatus.Completed]: 'Completed',
    [EngagementStatus.OnHold]: 'On hold',
};

const Engagements = () => {
    const navigate = useNavigate();
    const { data, error, loading } = useEngagementsQuery({ fetchPolicy: 'cache-and-network' });

    const pageHeader = (
        <header className="bg-background sticky top-0 z-10 flex h-12 w-full shrink-0 items-center gap-2 border-b">
            <div className="flex items-center gap-2 px-4">
                <SidebarTrigger className="-ml-1" />
                <Separator
                    className="h-4"
                    orientation="vertical"
                />
                <Breadcrumb>
                    <BreadcrumbList>
                        <BreadcrumbItem>
                            <ShieldCheck className="size-4" />
                            <BreadcrumbPage>Engagements</BreadcrumbPage>
                        </BreadcrumbItem>
                    </BreadcrumbList>
                </Breadcrumb>
            </div>
            <div className="ml-auto flex items-center gap-2 px-4">
                <Button
                    onClick={() => navigate('/engagements/new')}
                    size="sm"
                    variant="secondary"
                >
                    <Plus />
                    New Engagement
                </Button>
            </div>
        </header>
    );

    if (loading && !data) {
        return (
            <>
                {pageHeader}
                <div className="flex flex-col gap-4 p-4">
                    <StatusCard
                        description="Fetching engagement list..."
                        title="Loading"
                    />
                </div>
            </>
        );
    }

    if (error) {
        return (
            <>
                {pageHeader}
                <div className="flex flex-col gap-4 p-4">
                    <StatusCard
                        description={error.message}
                        title="Failed to load engagements"
                    />
                </div>
            </>
        );
    }

    const engagements = data?.engagements ?? [];

    if (engagements.length === 0) {
        return (
            <>
                {pageHeader}
                <div className="flex flex-col gap-4 p-4">
                    <StatusCard
                        action={
                            <Button
                                onClick={() => navigate('/engagements/new')}
                                variant="secondary"
                            >
                                <Plus />
                                New Engagement
                            </Button>
                        }
                        description="Create an engagement to group scanner imports, findings, and flows."
                        icon={<ShieldCheck className="text-muted-foreground size-8" />}
                        title="No engagements yet"
                    />
                </div>
            </>
        );
    }

    return (
        <>
            {pageHeader}
            <div className="flex flex-col gap-4 p-4 pt-4">
                <Table>
                    <TableHeader>
                        <TableRow>
                            <TableHead>Name</TableHead>
                            <TableHead>Client</TableHead>
                            <TableHead>Status</TableHead>
                            <TableHead title="Critical / High / Medium / Low / Info">C / H / M / L / I</TableHead>
                            <TableHead>Updated</TableHead>
                        </TableRow>
                    </TableHeader>
                    <TableBody>
                        {engagements.map((engagement) => (
                            <TableRow
                                className="hover:bg-muted/50 cursor-pointer"
                                key={engagement.id}
                                onClick={() => navigate(`/engagements/${engagement.id}`)}
                            >
                                <TableCell className="font-medium">
                                    <Link
                                        className="hover:underline"
                                        onClick={(e) => e.stopPropagation()}
                                        to={`/engagements/${engagement.id}`}
                                    >
                                        {engagement.name}
                                    </Link>
                                </TableCell>
                                <TableCell>{engagement.client}</TableCell>
                                <TableCell>
                                    <Badge variant={statusVariant[engagement.status]}>
                                        {statusLabel[engagement.status]}
                                    </Badge>
                                </TableCell>
                                <TableCell className="font-mono text-xs">
                                    <span className="font-medium text-red-500">
                                        {engagement.findingStats.critical}
                                    </span>
                                    <span className="text-muted-foreground"> / </span>
                                    <span className="text-orange-500">{engagement.findingStats.high}</span>
                                    <span className="text-muted-foreground"> / </span>
                                    <span className="text-yellow-500">{engagement.findingStats.medium}</span>
                                    <span className="text-muted-foreground"> / </span>
                                    <span>{engagement.findingStats.low}</span>
                                    <span className="text-muted-foreground"> / </span>
                                    <span className="text-muted-foreground">{engagement.findingStats.info}</span>
                                </TableCell>
                                <TableCell className="text-muted-foreground text-sm">
                                    {format(new Date(engagement.updatedAt), 'd MMM yyyy, HH:mm')}
                                </TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </div>
        </>
    );
};

export default Engagements;
