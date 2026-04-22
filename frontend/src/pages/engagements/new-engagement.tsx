import { type FormEvent, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'sonner';

import {
    Breadcrumb,
    BreadcrumbItem,
    BreadcrumbList,
    BreadcrumbPage,
} from '@/components/ui/breadcrumb';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { SidebarTrigger } from '@/components/ui/sidebar';
import { Textarea } from '@/components/ui/textarea';
import {
    EngagementsDocument,
    useCreateEngagementMutation,
} from '@/graphql/types';

const NewEngagement = () => {
    const navigate = useNavigate();
    const [name, setName] = useState('');
    const [client, setClient] = useState('');
    const [description, setDescription] = useState('');
    const [createEngagement, { error, loading }] = useCreateEngagementMutation({
        refetchQueries: [{ query: EngagementsDocument }],
    });

    const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();

        if (loading) {
            return;
        }

        try {
            const { data } = await createEngagement({
                variables: {
                    input: {
                        client: client.trim(),
                        description: description.trim() ? description.trim() : undefined,
                        name: name.trim(),
                    },
                },
            });

            if (data?.createEngagement?.id) {
                toast.success('Engagement created');
                navigate(`/engagements/${data.createEngagement.id}`);
            }
        } catch (err) {
            const message = err instanceof Error ? err.message : 'Failed to create engagement';
            toast.error(message);
        }
    };

    return (
        <>
            <header className="bg-background sticky top-0 z-10 flex h-12 shrink-0 items-center gap-2 border-b px-4">
                <SidebarTrigger className="-ml-1" />
                <Separator
                    className="mr-2 h-4"
                    orientation="vertical"
                />
                <Breadcrumb>
                    <BreadcrumbList>
                        <BreadcrumbItem>
                            <BreadcrumbPage>New engagement</BreadcrumbPage>
                        </BreadcrumbItem>
                    </BreadcrumbList>
                </Breadcrumb>
            </header>
            <div className="flex min-h-[calc(100dvh-3rem)] items-center justify-center p-4">
                <Card className="w-full max-w-2xl">
                    <CardContent className="flex flex-col gap-4 pt-6">
                        <div className="text-center">
                            <h1 className="text-2xl font-semibold">Create a new engagement</h1>
                            <p className="text-muted-foreground mt-2">
                                Group scanner imports, findings, and pentest flows under a single client engagement.
                            </p>
                        </div>
                        <form
                            className="flex flex-col gap-4"
                            onSubmit={handleSubmit}
                        >
                            <div className="flex flex-col gap-1.5">
                                <Label htmlFor="engagement-name">Name</Label>
                                <Input
                                    id="engagement-name"
                                    maxLength={255}
                                    onChange={(e) => setName(e.target.value)}
                                    placeholder="Q2 external pentest"
                                    required
                                    value={name}
                                />
                            </div>
                            <div className="flex flex-col gap-1.5">
                                <Label htmlFor="engagement-client">Client</Label>
                                <Input
                                    id="engagement-client"
                                    maxLength={255}
                                    onChange={(e) => setClient(e.target.value)}
                                    placeholder="Acme Corp"
                                    required
                                    value={client}
                                />
                            </div>
                            <div className="flex flex-col gap-1.5">
                                <Label htmlFor="engagement-description">Description</Label>
                                <Textarea
                                    id="engagement-description"
                                    maxHeight={240}
                                    minHeight={80}
                                    onChange={(e) => setDescription(e.target.value)}
                                    placeholder="Scope summary, rules of engagement, testing windows..."
                                    value={description}
                                />
                            </div>
                            <div className="flex items-center justify-end gap-2">
                                <Button
                                    onClick={() => navigate('/engagements')}
                                    type="button"
                                    variant="outline"
                                >
                                    Cancel
                                </Button>
                                <Button
                                    disabled={loading || !name.trim() || !client.trim()}
                                    type="submit"
                                >
                                    {loading ? 'Creating...' : 'Create'}
                                </Button>
                            </div>
                            {error && (
                                <p className="text-destructive text-sm">{error.message}</p>
                            )}
                        </form>
                    </CardContent>
                </Card>
            </div>
        </>
    );
};

export default NewEngagement;
